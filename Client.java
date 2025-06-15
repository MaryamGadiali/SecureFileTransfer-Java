import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;


public class Client {

    //Verifies the signature of the incoming message
    static boolean isSignatureValid(byte[] encryptedMessage, DataInputStream dataInputStream, PublicKey serverPublicKey) throws SignatureException, NoSuchAlgorithmException, IOException, InvalidKeyException{
        int incomingMessageLength = dataInputStream.readInt();
        byte[] incomingSignature = new byte[incomingMessageLength];
        dataInputStream.readFully(incomingSignature);

        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(serverPublicKey);
        signature.update(encryptedMessage); 
        return signature.verify(incomingSignature);
    }

    //Decrypts and verifies the returned 32 AES bytes from the server
    static byte[] receiveMessageFromServer(DataInputStream dataInputStream, PrivateKey clientPrivateKey, PublicKey serverPublicKey) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, SignatureException{
        int incomingMessageLength = dataInputStream.readInt();
        byte[] incomingEncryptedContents = new byte[incomingMessageLength];
        dataInputStream.readFully(incomingEncryptedContents);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, clientPrivateKey);
        
        boolean isSignatureValid = isSignatureValid(incomingEncryptedContents,dataInputStream,serverPublicKey);
        if (isSignatureValid){
            return cipher.doFinal(incomingEncryptedContents);
        }
        else{
            System.out.println("Failed signature verification");
            return null;
        }
    }

    //Communicates with the server to form 32 bytes to produce the AES key
    static byte[] authenticationAndKeyAgreement(String userId, PublicKey serverPublicKey, PrivateKey clientPrivateKey, DataOutputStream dataOutputStream, Socket clientSocket, DataInputStream dataInputStream) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException{
        
        //Creates the message consisting of the user's ID and 16 random bytes
        byte[] randomBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(randomBytes);
        byte[] userIdBytes = userId.getBytes();
        byte[] outgoingMessageByteLength = new byte[randomBytes.length+userIdBytes.length];
        ByteBuffer outgoingMessageBytesBuffer = ByteBuffer.wrap(outgoingMessageByteLength);
        outgoingMessageBytesBuffer.put(userIdBytes);
        outgoingMessageBytesBuffer.put(randomBytes);

        //Encrypts the message using the server's public key
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] outgoingMessageBytes = cipher.doFinal(outgoingMessageBytesBuffer.array());
    
        //Signs the encrypted message using the client's private key
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(clientPrivateKey);
        signature.update(outgoingMessageBytes);
        byte[] signedSignature = signature.sign();
 
        //Sends the encrypted message and signed signature to the server
        dataOutputStream.writeInt(outgoingMessageBytes.length);
        dataOutputStream.write(outgoingMessageBytes);
        dataOutputStream.writeInt(signedSignature.length);
        dataOutputStream.write(signedSignature);
        dataOutputStream.flush();

        //Waits until server sends 32 bit message back
        byte[] messageFromServer = receiveMessageFromServer(dataInputStream, clientPrivateKey, serverPublicKey);
        if (messageFromServer==null){
            System.out.println("Signature match failed");
            return null;
        }

        //Checks if the first 16 bytes of the received message are the same as the random bytes sent
        byte[] firstHalf = Arrays.copyOfRange(messageFromServer, 0, 16);
        if (!Arrays.equals(firstHalf,randomBytes)){
            System.out.println("Terminating connection");
            return null;
        }
        return messageFromServer;
    }
    
    static PublicKey getServerPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        File serverPubFile = new File("server.pub");
        byte[] publicKeyBytes = Files.readAllBytes(serverPubFile.toPath());
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(pubKeySpec);
    }
    
    static PrivateKey getClientPrivateKey(String userId) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        File clientPrivFile = new File(userId+".prv");
        byte[] privKeyBytes = Files.readAllBytes(clientPrivFile.toPath());
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(privKeySpec);
    }
        
        
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        
        String hostname = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2];

        PrivateKey clientPrivateKey = getClientPrivateKey(userId);
        PublicKey serverPublicKey = getServerPublicKey();

        try{
            Socket clientSocket = new Socket(hostname,port);
            DataOutputStream dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());
            DataInputStream dataInputStream = new DataInputStream(clientSocket.getInputStream());

            byte[] aes32bytes = authenticationAndKeyAgreement(userId, serverPublicKey, clientPrivateKey, dataOutputStream, clientSocket, dataInputStream);
            if (aes32bytes==null){
                System.out.println("authenticationAndKeyAgreement failed");
            }
            else{
                SecretKey aesKey = new SecretKeySpec(aes32bytes, "AES");  
                
                //File transmission stage
                byte[] iv=aes32bytes;
                while (true){
                    System.out.println("Enter command");
                    Scanner scanner = new Scanner(System.in);
                    String inputMessage = scanner.nextLine();
                    if (inputMessage.equals("ls") || inputMessage.startsWith("get ") || inputMessage.equals("bye")){
                        //Sends the corresponding command to the server
                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                        iv = messageDigest.digest(iv);
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        IvParameterSpec ivSpec = new IvParameterSpec(iv);
                        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
                        byte[] finalMessage = cipher.doFinal(inputMessage.getBytes());
                        dataOutputStream.writeInt(finalMessage.length);
                        dataOutputStream.write(finalMessage);
                        dataOutputStream.flush();

                        if (inputMessage.equals("bye")){
                            clientSocket.close();
                            break;
                        }

                        //Waits for server's response
                        int incomingMessageLength = dataInputStream.readInt();
                        byte[] incomingEncryptedContents = new byte[incomingMessageLength];
                        dataInputStream.readFully(incomingEncryptedContents);
                        iv = messageDigest.digest(iv);
                        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        ivSpec = new IvParameterSpec(iv);
                        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
                        incomingEncryptedContents = cipher.doFinal(incomingEncryptedContents);
                        String receivedMessage = new String(incomingEncryptedContents);

                        //Saves the retrieved file locally
                        if (inputMessage.startsWith("get ") && !receivedMessage.equals("File does not exist")){
                            String fileName = inputMessage.substring(4, inputMessage.length());
                            FileOutputStream fileOutputStream = new FileOutputStream(fileName);
                            fileOutputStream.write(receivedMessage.getBytes());
                            fileOutputStream.close();
                        }
                        else if (inputMessage.equals("ls")){
                            System.out.println(receivedMessage); 
                        }
                        else if (receivedMessage.equals("File does not exist")){
                            System.out.println("File does not exist");
                        }
                    }
                    else{
                        System.out.println("Invalid command");
                    }
                }
            }
        }
        catch (SocketException e){
            System.err.println("Server stopped communicating");
        }
        catch (Exception e){
            System.err.println("Error has occured");
            e.printStackTrace();
        }
    }  
}

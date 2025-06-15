import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Server {
    
    public static void main(String[] args) throws Exception {
        
        int port = Integer.parseInt(args[0]);
        String userId = "server";

        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Waiting for client connection");

        try{
            while (true){
                Socket clientSocket = serverSocket.accept();
                System.out.println("Received new client connection");
            
                DataInputStream dataInputStream = new DataInputStream(clientSocket.getInputStream());
                DataOutputStream dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());
                
                //Decrypts the incoming message with the server's private key
                int incomingMessageLength = dataInputStream.readInt();
                byte[] incomingEncryptedContents = new byte[incomingMessageLength];
                dataInputStream.readFully(incomingEncryptedContents);

                File serverPrivFile = new File(userId+".prv");
                byte[] privKeyBytes = Files.readAllBytes(serverPrivFile.toPath());
                PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PrivateKey serverPrivKey = keyFactory.generatePrivate(privKeySpec);
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, serverPrivKey);
            
                //Seperates the client's user ID and their random 16 bytes
                byte[] receivedMessage = cipher.doFinal(incomingEncryptedContents);
                int clientIDBytesSize = receivedMessage.length-16;
                String clientIdName = (new String(receivedMessage)).substring(0,clientIDBytesSize);
                System.out.println("Connected client has userID: "+clientIdName);
                byte[] clientRandomBytes = Arrays.copyOfRange(receivedMessage, clientIDBytesSize, receivedMessage.length);
                
                //Verifies the signature of the incoming message with the client's public key
                incomingMessageLength = dataInputStream.readInt();
                byte[] incomingSignature = new byte[incomingMessageLength];
                dataInputStream.readFully(incomingSignature);

                File clientPubFile = new File(clientIdName+".pub");
                byte[] pubKeyBytes = Files.readAllBytes(clientPubFile.toPath());
                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
                PublicKey clientPubKey = keyFactory.generatePublic(pubKeySpec);

                Signature signature = Signature.getInstance("SHA1withRSA");
                signature.initVerify(clientPubKey);
                signature.update(incomingEncryptedContents); 
                boolean verificationResult = signature.verify(incomingSignature);
            
                if (verificationResult){
                    //Generates its own 16 random bytes and concatenates it after the client's 16 bytes to form the AES bytes
                    byte[] randomBytes = new byte[16];
                    SecureRandom secureRandom = new SecureRandom();
                    secureRandom.nextBytes(randomBytes);
                    byte[] outgoingMessageByteLength = new byte[randomBytes.length+clientRandomBytes.length];
                    ByteBuffer outgoingMessageBytesBuffer = ByteBuffer.wrap(outgoingMessageByteLength);
                    outgoingMessageBytesBuffer.put(clientRandomBytes);
                    outgoingMessageBytesBuffer.put(randomBytes);

                    //Encrypts the message and generates the signature and sends them to the client
                    cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, clientPubKey); //this should use the server's public rsa key
                    byte[] outgoingMessageBytes = cipher.doFinal(outgoingMessageBytesBuffer.array());

                    signature = Signature.getInstance("SHA1withRSA");
                    signature.initSign(serverPrivKey);
                    signature.update(outgoingMessageBytes); 
                    byte[] signedSignature = signature.sign();

                    dataOutputStream.writeInt(outgoingMessageBytes.length);
                    dataOutputStream.write(outgoingMessageBytes);
                    dataOutputStream.writeInt(signedSignature.length);
                    dataOutputStream.write(signedSignature);
                    dataOutputStream.flush();

                    //Converts the 32 bytes into a secret key
                    Base64.Encoder encoder = Base64.getEncoder();
                    String aesPlaintextStr = encoder.encodeToString(outgoingMessageBytesBuffer.array());
                    System.out.println("The 32 plaintext bytes are: ");
                    System.out.println(aesPlaintextStr);
                    SecretKey aesKey = new SecretKeySpec(outgoingMessageBytesBuffer.array(), "AES");

                    //File transmission stage
                    byte[] iv = outgoingMessageBytesBuffer.array();
                    while (true){
                        //Server will wait until the client makes a request
                        incomingMessageLength = dataInputStream.readInt();
                        incomingEncryptedContents = new byte[incomingMessageLength];
                        dataInputStream.readFully(incomingEncryptedContents);

                        //Decrypt and handles the request command
                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                        iv = messageDigest.digest(iv);
                        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        IvParameterSpec ivSpec = new IvParameterSpec(iv);
                        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
                        receivedMessage = cipher.doFinal(incomingEncryptedContents);
                        String receivedCommand = new String(receivedMessage);
                
                        //Retrieves the list of files in the server directory that are non prv and sends to the client
                        if (receivedCommand.equals("ls")){
                            StringBuilder fileNames = new StringBuilder("");
                            File[] files = new File("./").listFiles(); 
                            for (File f : files) {
                                if (f.isFile() && !f.getName().endsWith(".prv")) { 
                                    fileNames.append(f.getName());
                                    fileNames.append("\n");
                                }
                            }

                            byte[] fileNameMessage;
                            if (!fileNames.equals("")){
                                fileNameMessage = fileNames.toString().getBytes();
                            }
                            else{
                                fileNameMessage = "No files available".getBytes();
                            }
                            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            iv = messageDigest.digest(iv);
                            ivSpec = new IvParameterSpec(iv);
                            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
                            byte[] encryptedMessage = cipher.doFinal(fileNameMessage);
                            dataOutputStream.writeInt(encryptedMessage.length);
                            dataOutputStream.write(encryptedMessage);
                            dataOutputStream.flush();
                        }
                        //Retrieves the file contents of the requested file and sends to the client
                        else if (receivedCommand.startsWith("get ")){
                            byte[] fileContents = new byte[0];
                            String fileName = receivedCommand.substring(4,receivedCommand.length());
                            
                            try{
                                File targetFile = new File(fileName);
                                fileContents = Files.readAllBytes(targetFile.toPath());
                                System.out.println(fileName+" has been requested from client");
                            }
                            catch (FileNotFoundException e){
                                fileContents="File does not exist".getBytes();
                            }
                            catch (NoSuchFileException e){
                                fileContents="File does not exist".getBytes();
                            }
                            catch (Exception e){
                                e.printStackTrace();
                            }

                            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            iv = messageDigest.digest(iv);
                            ivSpec = new IvParameterSpec(iv);
                            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
                            byte[] encryptedMessage = cipher.doFinal(fileContents);
                            dataOutputStream.writeInt(encryptedMessage.length);
                            dataOutputStream.write(encryptedMessage);
                            dataOutputStream.flush();
                        }
                        //Ends the client connection and will wait for a new client connection
                        else if (receivedCommand.equals("bye")){
                            System.out.println("Ending client connection");
                            clientSocket.close();
                            break;
                        }
                        else{
                            System.out.println("Invalid command sent");
                        }
                    }
                }
                else{
                    System.out.println("Failed signature verification");
                    System.out.println("Ending client connection");
                    clientSocket.close();
                }
            }
        }
        catch (BadPaddingException e){
            System.err.println("There is a decryption problem on the server side, ending program");
        }
        catch (Exception e){
            System.err.println("Error has occured");
            e.printStackTrace();
        }
    }
}
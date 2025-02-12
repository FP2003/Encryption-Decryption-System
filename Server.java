import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.Cipher;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class Server {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java Server <port>");
            return;
        }

        int port = Integer.parseInt(args[0]);
        System.out.println("Server is running on port: " + port);

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected.");
                handleClient(clientSocket);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket clientSocket) {
        try (DataInputStream in = new DataInputStream(clientSocket.getInputStream());
             DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream())) {

            System.out.println("Client connected.");

            // Receive encrypted data
            String encryptedData = in.readUTF();
            System.out.println("✅ Received Encrypted Data: \n" + encryptedData);

            // Receive signature
            String signature = in.readUTF();
            System.out.println("✅ Received Signature: \n" + signature);
            
            // Load Server's private key (server.prv)
            PrivateKey privateKey = loadPrivateKey("server.prv");

            // Decode Base64 encrypted data
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);

            // Decrypt using RSA
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            //Convert decrypted bytes to string
            String combinedData = new String(decryptedBytes, "UTF-8");

            System.out.println("Decrypted Data: " + combinedData);
            String userId = combinedData.substring(0, combinedData.length() - 24); // Assuming userid is a simple string
            String randomBytesBase64 = combinedData.substring(combinedData.length() - 24); // Last 24 characters are Base64-encoded random bytes
            System.out.println("Extracted User ID: " + userId);
            System.out.println("Extracted Random Bytes: " + randomBytesBase64);



            PublicKey clientPublicKey = loadPublicKey(userId + ".pub"); // Load client's public key using extracted userId
            Signature sig = Signature.getInstance("SHA1withRSA"); // Initialize RSA signature verification using SHA1withRSA
            sig.initVerify(clientPublicKey); // Set up signature verification with client's public key
            sig.update(Base64.getDecoder().decode(encryptedData)); // Feed the original encrypted data into the verification process
            boolean isValid = sig.verify(Base64.getDecoder().decode(signature)); // Verify signature against received signature
            
            // AUTHENTICATION FEEDBACK
            if (isValid) {
                System.out.println("Signature verified successfully."); // Log successful verification
                out.writeUTF("Server: Authentication successful "); // Notify client of successful authentication
            } else {
                System.out.println("Signature verification failed."); // Log failed verification
                out.writeUTF("Server: Authentication failed."); // Notify client of failed authentication
                return; // Terminate the connection if authentication fails
            }


            //BULLET POINT 3 NOW 
            // COVERS BULLET POINT 3
            byte[] sPrivateBytes = new byte[16];
            new SecureRandom().nextBytes(sPrivateBytes);
            String s_RandomBytesBase64 = Base64.getEncoder().encodeToString(sPrivateBytes);

            System.out.println("Generated Server Random Bytes: "+ s_RandomBytesBase64);

            // COVERS BULLET POINT 3
            String combinedRandomBytes = randomBytesBase64 + s_RandomBytesBase64;

            // COVERS BULLET POINT 3
            PublicKey c_PublicKey = loadPublicKey(userId + ".pub");
            Cipher encryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encryptionCipher.init(Cipher.ENCRYPT_MODE, c_PublicKey);
            byte[] encrypted_combinedRandomBytes = encryptionCipher.doFinal(combinedRandomBytes.getBytes("UTF-8"));
            String encrypted_combinedRandomBytesBase64 = Base64.getEncoder().encodeToString(encrypted_combinedRandomBytes);

            System.out.println("Encrypted Combined Random Bytes: "+ encrypted_combinedRandomBytesBase64);

            // COVERS BULLET POINT 3
            Signature s_Signature = Signature.getInstance("SHA1withRSA");
            s_Signature.initSign(privateKey);
            s_Signature.update(encrypted_combinedRandomBytes);
            byte[] s_Sig = s_Signature.sign();
            String s_SignatureBase64 = Base64.getEncoder().encodeToString(s_Sig);

            System.out.println("Server Signature: "+ s_Sig);
            
            // COVERS BULLET POINT 3
            out.writeUTF(encrypted_combinedRandomBytesBase64);
            out.writeUTF(s_SignatureBase64);

            System.out.println("The server sent encrypted combined random butes and server signature to client.");

            

            // Send a basic confirmation message to the client
            //out.writeUTF("Server: Encrypted data and signature received successfully.");

        } catch (IOException e) {
            System.err.println("❌ ERROR: Issue while reading data from client.");
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("❌ ERROR: Issue while decrypting data.");
            e.printStackTrace();
        }








    }

    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(prvSpec);
    }

    private static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(pubSpec);
    }
}






/* 
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;

public class Server {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java Server <port>");
            return;
        }
        
        int port = Integer.parseInt(args[0]);
        System.out.println("Server is running on port: " + port);
        
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected.");
                handleClient(clientSocket);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket clientSocket) {
        try (DataInputStream in = new DataInputStream(clientSocket.getInputStream());
             DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream())) {

            // Simple authentication (will be replaced by RSA authentication later)
            String clientMessage = in.readUTF();
            System.out.println("Received from client: " + clientMessage);
            out.writeUTF("Server: Authentication Successful");

            // Handle basic commands
            while (true) {
                String command = in.readUTF();
                if (command.equals("bye")) {
                    System.out.println("Client disconnected.");
                    break;
                } else if (command.equals("ls")) {
                    listFiles(out);
                } else if (command.startsWith("get ")) {
                    sendFile(command.substring(4), out);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void listFiles(DataOutputStream out) throws IOException {
        File dir = new File(".");
        String[] files = dir.list();
        if (files != null) {
            out.writeInt(files.length);
            for (String file : files) {
                out.writeUTF(file);
            }
        } else {
            out.writeInt(0);
        }
    }

    private static void sendFile(String filename, DataOutputStream out) throws IOException {
        File file = new File(filename);
        if (!file.exists()) {
            out.writeInt(0);
            return;
        }

        byte[] fileBytes = Files.readAllBytes(file.toPath()); // ✅ Fixed with import
        out.writeInt(fileBytes.length);
        out.write(fileBytes);
    }
}
*/

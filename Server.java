import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class Server {
    private static SecretKey aesKey;
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

            //System.out.println("Encrypted Combined Random Bytes: "+ encrypted_combinedRandomBytesBase64);

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

            byte[] sharedSecret = combinedRandomBytes.getBytes("UTF-8");
            SecretKey aesKey = generateAESKey(sharedSecret);
            System.out.println("🔐 AES Key Generated: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));
            aesKey = generateAESKey(sharedSecret);
            //System.out.println("The server sent encrypted combined random butes and server signature to client.");

            

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

    private static SecretKey generateAESKey(byte[] sharedSecret) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hashedKey = sha256.digest(sharedSecret);
        return new SecretKeySpec(hashedKey, "AES");
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

    private static byte[] encryptAES(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // AES Encryption
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
    
    private static byte[] decryptAES(SecretKey key, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // AES Decryption
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

}





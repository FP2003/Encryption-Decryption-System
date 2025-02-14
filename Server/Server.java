import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class Server {
    private static SecretKey aesKey;
    // IV variables for encryption and decryption
    private static byte[] currentIVEnc;
    private static byte[] currentIVDec;

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

            // Receive encrypted data from the client
            String encryptedData = in.readUTF();
            System.out.println("✅ Received Encrypted Data: \n" + encryptedData);

            // Receive the client's signature
            String signature = in.readUTF();
            System.out.println("✅ Received Signature: \n" + signature);
            
            // Load Server's private key (server.prv)
            PrivateKey privateKey = loadPrivateKey("Server.prv");

            // Decode and decrypt the client's encrypted data using RSA/ECB/PKCS1Padding
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            // Convert decrypted bytes to string and extract the userid and client's 16 random bytes
            String combinedData = new String(decryptedBytes, "UTF-8");
            System.out.println("Decrypted Data: " + combinedData);
            String userId = combinedData.substring(0, combinedData.length() - 24);
            String randomBytesBase64 = combinedData.substring(combinedData.length() - 24);
            System.out.println("Extracted User ID: " + userId);
            System.out.println("Extracted Random Bytes: " + randomBytesBase64);

            // Verify the client's signature using the client's public key (userId.pub)
            PublicKey clientPublicKey = loadPublicKey(userId + ".pub");
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(clientPublicKey);
            sig.update(Base64.getDecoder().decode(encryptedData));
            boolean isValid = sig.verify(Base64.getDecoder().decode(signature));
            
            if (isValid) {
                System.out.println("Signature verified successfully.");
                out.writeUTF("Server: Authentication successful ");
            } else {
                System.out.println("Signature verification failed.");
                out.writeUTF("Server: Authentication failed.");
                return;
            }

            // Generate server's own 16 random bytes and encode them in Base64
            byte[] sPrivateBytes = new byte[16];
            new SecureRandom().nextBytes(sPrivateBytes);
            String s_RandomBytesBase64 = Base64.getEncoder().encodeToString(sPrivateBytes);
            System.out.println("Generated Server Random Bytes: " + s_RandomBytesBase64);

            // Concatenate the client's Base64 random bytes and the server's Base64 random bytes
            String combinedRandomBytes = randomBytesBase64 + s_RandomBytesBase64;

            // Encrypt the combined random bytes using the client's public key
            PublicKey c_PublicKey = loadPublicKey(userId + ".pub");
            Cipher encryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encryptionCipher.init(Cipher.ENCRYPT_MODE, c_PublicKey);
            byte[] encrypted_combinedRandomBytes = encryptionCipher.doFinal(combinedRandomBytes.getBytes("UTF-8"));
            String encrypted_combinedRandomBytesBase64 = Base64.getEncoder().encodeToString(encrypted_combinedRandomBytes);

            // Sign the encrypted combined random bytes using the server's private key
            Signature s_Signature = Signature.getInstance("SHA1withRSA");
            s_Signature.initSign(privateKey);
            s_Signature.update(encrypted_combinedRandomBytes);
            byte[] s_Sig = s_Signature.sign();
            String s_SignatureBase64 = Base64.getEncoder().encodeToString(s_Sig);
            System.out.println("Server Signature: " + s_SignatureBase64);
            
            // Send the encrypted combined random bytes and its signature to the client
            out.writeUTF(encrypted_combinedRandomBytesBase64);
            out.writeUTF(s_SignatureBase64);

            // ----- Updated AES Key Derivation -----
            // The combined string contains two Base64 parts:
            // - First 24 characters: client's 16 random bytes (Base64-encoded)
            // - The remainder: server's 16 random bytes (Base64-encoded)
            String clientSentRandomBytes = combinedRandomBytes.substring(0, 24);
            String serverGeneratedRandomBytes = combinedRandomBytes.substring(24);

            byte[] clientBytes = Base64.getDecoder().decode(clientSentRandomBytes);
            byte[] serverBytes = Base64.getDecoder().decode(serverGeneratedRandomBytes);

            byte[] sharedSecret = new byte[clientBytes.length + serverBytes.length];
            System.arraycopy(clientBytes, 0, sharedSecret, 0, clientBytes.length);
            System.arraycopy(serverBytes, 0, sharedSecret, clientBytes.length, serverBytes.length);

            // Directly create the AES key from the 32-byte shared secret.
            aesKey = new SecretKeySpec(sharedSecret, "AES");
            System.out.println("🔐 AES Key Generated: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));
            // ----- End Updated AES Key Derivation -----

            // Initialize the IVs for encryption and decryption by computing MD5 of the shared secret.
            currentIVEnc = computeMD5(sharedSecret);
            currentIVDec = computeMD5(sharedSecret);

            // Process subsequent commands using AES/CBC/PKCS5Padding.
            while (true) {
                String encryptedCommandBase64 = in.readUTF();
                byte[] encryptedCommand = Base64.getDecoder().decode(encryptedCommandBase64);
                byte[] decryptedCommandBytes = decryptAES_CBC(encryptedCommand);
                String command = new String(decryptedCommandBytes, "UTF-8");
                System.out.println("Received command: " + command);

                if (command.equalsIgnoreCase("bye")) {
                    String goodbyeMessage = "bye";
                    byte[] encryptedGoodbye = encryptAES_CBC(goodbyeMessage.getBytes("UTF-8"));
                    out.writeUTF(Base64.getEncoder().encodeToString(encryptedGoodbye));
                    System.out.println("Client requested bye. Closing connection.");
                    break;
                }
                // You can add handling for "ls" and "get" commands here.
            }

        } catch (IOException e) {
            System.err.println("❌ ERROR: Issue while reading data from client.");
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("❌ ERROR: Issue while decrypting data.");
            e.printStackTrace();
        }
    }

    // Helper method to compute MD5 hash (used to generate and update IVs)
    private static byte[] computeMD5(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(input);
    }

    // Updated AES encryption routine using CBC mode with IV update.
    private static byte[] encryptAES_CBC(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(currentIVEnc);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] ciphertext = cipher.doFinal(data);
        // Update the IV: compute MD5 of the current IV.
        currentIVEnc = computeMD5(currentIVEnc);
        return ciphertext;
    }

    // Updated AES decryption routine using CBC mode with IV update.
    private static byte[] decryptAES_CBC(byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(currentIVDec);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        byte[] plaintext = cipher.doFinal(encryptedData);
        // Update the IV: compute MD5 of the current IV.
        currentIVDec = computeMD5(currentIVDec);
        return plaintext;
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

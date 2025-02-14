import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Client {
    private static String firstGeneratedRandomBytesBase64; // Store the client's random bytes (Base64)
    private static SecretKey aesKey; // AES key after key exchange
    // IV variables for encryption and decryption
    private static byte[] currentIVEnc;
    private static byte[] currentIVDec;
    
    public static void main(String[] args) {
        // Ensure 3 arguments are provided: <host> <port> <userid>
        if (args.length != 3) {
            System.out.println("Use: java Client <host> <port> <userid>");
            return;
        }

        String serverHost = args[0];
        int serverPort = Integer.parseInt(args[1]);
        String userId = args[2];

        // Main loop: try to connect and process commands
        while (true) {
            try (Socket socket = new Socket(serverHost, serverPort);
                 DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                 DataInputStream in = new DataInputStream(socket.getInputStream())) {

                // Perform the initial key exchange and authentication
                String[] result = serverConnectionCheck(userId);
                String encryptedData = result[0];
                String signature = result[1];

                // Send the encrypted data and signature to the server
                out.writeUTF(encryptedData);
                out.writeUTF(signature);

                // Receive authentication confirmation from the server
                String serverResponse = in.readUTF();
                System.out.println("Server Response: " + serverResponse);

                if (serverResponse.contains("Authentication successful")) {
                    receiveServerResponse(in, userId);
                }

                // Command loop: ls, get, bye
                Scanner scanner = new Scanner(System.in);
                while (true) {
                    System.out.print("Enter command (ls, get <filename>, bye): ");
                    String command = scanner.nextLine().trim();

                    // Encrypt the command using AES/CBC/PKCS5Padding with the current IV
                    byte[] encryptedCommand = encryptAES_CBC(command.getBytes("UTF-8"));
                    String encryptedCommandBase64 = Base64.getEncoder().encodeToString(encryptedCommand);
                    out.writeUTF(encryptedCommandBase64);

                    // Read and decrypt the server's response
                    String encryptedResponseBase64 = in.readUTF();
                    byte[] decryptedResponse = decryptAES_CBC(Base64.getDecoder().decode(encryptedResponseBase64));
                    String response = new String(decryptedResponse, "UTF-8");

                    System.out.println("Server Response: " + response);

                    if (command.equalsIgnoreCase("bye")) {
                        System.out.println("Exiting client...");
                        return;
                    }
                }

            } catch (Exception e) {
                System.err.println("An error occurred: " + e.getMessage());
                e.printStackTrace();
                System.out.println("Retrying connection in 5 seconds...");
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException ie) {
                    System.err.println("Retry interrupted.");
                }
            }
        }
    }

    // Prepares the authentication message by generating 16 random bytes and combining them with the userId.
    public static String[] serverConnectionCheck(String userId) throws Exception {
        // Generate 16 fresh random bytes for the client
        byte[] randomBytes = new byte[16];
        new SecureRandom().nextBytes(randomBytes);
        firstGeneratedRandomBytesBase64 = Base64.getEncoder().encodeToString(randomBytes);

        // Combine the userId with the Base64-encoded random bytes
        String combinedData = userId + firstGeneratedRandomBytesBase64;
        System.out.println("Combined Data: " + combinedData);
        byte[] dataToEncrypt = combinedData.getBytes("UTF-8");

        // Load the server's public key (assumed to be in the local folder as "Server.pub")
        PublicKey serverPublicKey = loadPublicKey("Server.pub");
        // Load the client's private key (assumed to be in the local folder as "<userId>.prv")
        PrivateKey userPrivateKey = loadPrivateKey(userId + ".prv");

        // Encrypt the combined data using RSA/ECB/PKCS1Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedData = cipher.doFinal(dataToEncrypt);

        // Sign the encrypted data using SHA1withRSA
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(userPrivateKey);
        signature.update(encryptedData);
        byte[] signedData = signature.sign();

        return new String[]{
            Base64.getEncoder().encodeToString(encryptedData),
            Base64.getEncoder().encodeToString(signedData)
        };
    }

    // Processes the server's response, verifies it, and generates the AES key.
    private static void receiveServerResponse(DataInputStream in, String userId) throws Exception {
        // Receive the server's encrypted combined random bytes and signature
        String encryptedCombinedBytesBase64 = in.readUTF();
        System.out.println("✅ Received Encrypted Combined Random Bytes: \n" + encryptedCombinedBytesBase64);

        String serverSignatureBase64 = in.readUTF();
        System.out.println("✅ Received Server Signature: \n" + serverSignatureBase64);

        byte[] encryptedCombinedBytes = Base64.getDecoder().decode(encryptedCombinedBytesBase64);
        byte[] serverSignature = Base64.getDecoder().decode(serverSignatureBase64);

        // Decrypt the combined random bytes using the client's private key
        PrivateKey clientPrivateKey = loadPrivateKey(userId + ".prv");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, clientPrivateKey);
        byte[] decryptedCombinedBytes = cipher.doFinal(encryptedCombinedBytes);
        String combinedRandomBytes = new String(decryptedCombinedBytes, "UTF-8");
        System.out.println("🔓 Decrypted Combined Random Bytes: " + combinedRandomBytes);

        // The first 24 characters correspond to the client's random bytes (Base64-encoded)
        String clientSentRandomBytes = combinedRandomBytes.substring(0, 24);
        // The remaining characters represent the server's random bytes (Base64-encoded)
        String serverGeneratedRandomBytes = combinedRandomBytes.substring(24);
        System.out.println("🔑 Client's Original Random Bytes: " + clientSentRandomBytes);
        System.out.println("🔑 Server's Generated Random Bytes: " + serverGeneratedRandomBytes);

        // Verify the server's signature
        PublicKey serverPublicKey = loadPublicKey("Server.pub");
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(serverPublicKey);
        sig.update(encryptedCombinedBytes);
        boolean isVerified = sig.verify(serverSignature);
        if (isVerified) {
            System.out.println("✅ Server's Signature Verified Successfully!");
        } else {
            System.out.println("❌ Server's Signature Verification Failed!");
            throw new SecurityException("Server authentication failed.");
        }

        // Final validation: Ensure the client's original random bytes match what was sent
        if (!clientSentRandomBytes.equals(firstGeneratedRandomBytesBase64)) {
            System.out.println("❌ Random byte mismatch! Possible attack detected.");
            throw new SecurityException("Random byte mismatch. Terminating connection.");
        }

        // Generate the AES key using the professor's suggested method:
        // Decode the client's random bytes (16 bytes expected) from Base64
        byte[] clientRandomBytes = Base64.getDecoder().decode(firstGeneratedRandomBytesBase64);
        // Extract and decode the server's random bytes (16 bytes expected)
        byte[] serverRandomBytes = Base64.getDecoder().decode(serverGeneratedRandomBytes);

        // Combine the two arrays into a single shared secret (32 bytes total)
        byte[] sharedSecret = new byte[clientRandomBytes.length + serverRandomBytes.length];
        System.arraycopy(clientRandomBytes, 0, sharedSecret, 0, clientRandomBytes.length);
        System.arraycopy(serverRandomBytes, 0, sharedSecret, clientRandomBytes.length, serverRandomBytes.length);

        // Directly create the AES key from the shared secret
        aesKey = new SecretKeySpec(sharedSecret, "AES");
        System.out.println("🔐 AES Key Generated: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));

        // Initialize the IVs for encryption and decryption by computing MD5 of the shared secret.
        currentIVEnc = computeMD5(sharedSecret);
        currentIVDec = computeMD5(sharedSecret);
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

    private static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(pubSpec);
    }

    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(prvSpec);
    }
}

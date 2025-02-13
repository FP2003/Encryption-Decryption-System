import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.spec.SecretKeySpec;

public class Client {
    private static String firstGeneratedRandomBytesBase64; // ✅ Store the original random bytes for validation
    private static SecretKey aesKey; // 🚀 Store AES key after key exchange

    public static void main(String[] args) {
        // Ensures 3 commands (arguements) are provided. If not, user will see a message helping them understand the format.
        if (args.length != 3) {
            System.out.println("Use: java Client <host> <port> <userid>");
            return;
        }

        // The 3 necessary commands are assigned with variables which we use to connect with server and obtain userId.
        String serverHost = args[0];
        int serverPort = Integer.parseInt(args[1]);
        String userId = args[2];

        // Keep the script connection running using a while loop until exited manualy otherwise.
        while (true) {

            // Attempts to connect using serverHost and serverPort variables.
            try (Socket socket = new Socket(serverHost, serverPort);
                 DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                 DataInputStream in = new DataInputStream(socket.getInputStream())) {

                // Calls serverConnectionCheck to get encrypted data and signature, passing through the userId.
                String[] result = serverConnectionCheck(userId);
                String encryptedData = result[0];
                String signature = result[1];

                // Send encrypted data and signature to the server
                out.writeUTF(encryptedData);
                out.writeUTF(signature);
                //System.out.println("Sent encrypted data and signature to the server.");

                // Receive confirmation from the server
                String serverResponse = in.readUTF();
                System.out.println("Server Response: " + serverResponse);

                // If authentication is successful, receive server's encrypted random bytes and signature
                if (serverResponse.contains("Authentication successful")) {
                    receiveServerResponse(in, userId); // ✅ Call function to process server's response
                }

                // Keep the system running, allowing the user to continue interacting and listen to potential commands.
                // -- COMMANDS --
                // ls - request for the server to send a list of filenames of all files available for download.
                // get - TODO
                // bye - client has no further requests. Both sides end connection. The client quits, the server waits for next client.
                Scanner scanner = new Scanner(System.in);
                while (true) {
                    System.out.print("Enter command (ls, get <filename>, bye): ");
                    String command = scanner.nextLine().trim();

                    // Encrypt the command before sending
                    byte[] encryptedCommand = encryptAES(aesKey, command.getBytes("UTF-8"));
                    String encryptedCommandBase64 = Base64.getEncoder().encodeToString(encryptedCommand);
                    
                    out.writeUTF(encryptedCommandBase64); // Send encrypted command

                    // Receive and decrypt the response from server
                    String encryptedResponseBase64 = in.readUTF();
                    byte[] decryptedResponse = decryptAES(aesKey, Base64.getDecoder().decode(encryptedResponseBase64));
                    String response = new String(decryptedResponse, "UTF-8");

                    System.out.println("Server Response: " + response);

                    if (command.equalsIgnoreCase("bye")) {
                        System.out.println("Exiting client...");
                        return;
                    }
                }


            // Catches errors and prints a message. Tries to reconnect after 5 seconds, if failed will print another error.
            } catch (Exception e) {
                System.err.println("An error occurred: " + e.getMessage());
                e.printStackTrace();
                System.out.println("Retrying connection in 5 seconds...");
                try {
                    Thread.sleep(5000); // Wait 5 seconds before retrying connection
                } catch (InterruptedException ie) {
                    System.err.println("Retry interrupted.");
                }
            }
        }
    }

    // Once connected to the server, passes the userId and generates 16 random bytes. Both combined into a variable which is-
    // encrypted with RSA/ECB/PKCS1Padding, RSAkeys to prove the identity of client.
    public static String[] serverConnectionCheck(String userId) throws Exception {
        
        // Generate 16 fresh random bytes
        byte[] randomBytes = new byte[16];
        new SecureRandom().nextBytes(randomBytes);

        // Store the random bytes for later validation
        firstGeneratedRandomBytesBase64 = Base64.getEncoder().encodeToString(randomBytes); 

        // Combine userId and random bytes into a readable string
        String combinedData = userId + firstGeneratedRandomBytesBase64;
        System.out.println("Combined Data: " + combinedData);

        // Convert combined data to bytes
        byte[] dataToEncrypt = combinedData.getBytes("UTF-8");

        // Load Server's public key (Server.pub)
        PublicKey serverPublicKey = loadPublicKey("Server.pub");
        // Load User's private key (Alice.prv)
        PrivateKey userPrivateKey = loadPrivateKey(userId + ".prv");

        // Encrypt the combined userId + random bytes using RSA/ECB/PKCS1Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedData = cipher.doFinal(dataToEncrypt);

        // Sign the encrypted data using SHA1withRSA
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(userPrivateKey);
        signature.update(encryptedData);
        byte[] signedData = signature.sign();

        // Convert encrypted data and signature to Base64
        return new String[]{
            Base64.getEncoder().encodeToString(encryptedData),
            Base64.getEncoder().encodeToString(signedData)
        };
    }

    private static void receiveServerResponse(DataInputStream in, String userId) throws Exception {
        // Receive the encrypted combined random bytes from the server
        String encryptedCombinedBytesBase64 = in.readUTF();
        System.out.println("✅ Received Encrypted Combined Random Bytes: \n" + encryptedCombinedBytesBase64);

        // Receive the server's signature
        String serverSignatureBase64 = in.readUTF();
        System.out.println("✅ Received Server Signature: \n" + serverSignatureBase64);

        // Decode Base64
        byte[] encryptedCombinedBytes = Base64.getDecoder().decode(encryptedCombinedBytesBase64);
        byte[] serverSignature = Base64.getDecoder().decode(serverSignatureBase64);

        // Load the client's private key to decrypt the combined random bytes
        PrivateKey clientPrivateKey = loadPrivateKey(userId + ".prv");

        // Decrypt using RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, clientPrivateKey);
        byte[] decryptedCombinedBytes = cipher.doFinal(encryptedCombinedBytes);

         

        // Convert decrypted bytes to string
        String combinedRandomBytes = new String(decryptedCombinedBytes, "UTF-8");

        System.out.println("🔓 Decrypted Combined Random Bytes: " + combinedRandomBytes);

        // Extract the first 16 bytes (should match the client's original random bytes)
        String clientSentRandomBytes = combinedRandomBytes.substring(0, 24);
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
        

        // Final validation: Ensure the first 16 bytes match the client's original random bytes
        if (!clientSentRandomBytes.equals(firstGeneratedRandomBytesBase64)) {
            System.out.println("❌ Random byte mismatch! Possible attack detected.");
            throw new SecurityException("Random byte mismatch. Terminating connection.");
        }

        //Generate the AES key
        byte[] sharedSecret = combinedRandomBytes.getBytes("UTF-8");
        SecretKey aesKey = generateAESKey(sharedSecret);
        System.out.println("🔐 AES Key Generated: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));
        aesKey = generateAESKey(sharedSecret); // Correctly assigns to the global AES key

    }

    private static SecretKey generateAESKey(byte[] sharedSecret) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hashedKey = sha256.digest(sharedSecret);
        return new SecretKeySpec(hashedKey, "AES");
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

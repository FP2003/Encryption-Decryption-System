import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;

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

            // Receive encrypted data and signature
            // COVERS BULLET POINT 2
            String encryptedData = in.readUTF();
            String signature = in.readUTF();

            // Print the received values
            System.out.println("Received Encrypted Data: " + encryptedData);
            System.out.println("Received Signature: " + signature);

            // Step 1: Load the server's private key
            PrivateKey serverPrivateKey = loadPrivateKey("server.prv");

            // Step 2: Decrypt the encrypted data
            // COVERS BULLET POINT 2

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            String combinedData = new String(decryptedBytes, "UTF-8");

            System.out.println("Decrypted Data: " + combinedData);

            // Step 3: Extract the userid and random bytes
            // COVERS BULLET POINT 2
            String userId = combinedData.substring(0, combinedData.length() - 24); // Assuming userid is a simple string
            String randomBytesBase64 = combinedData.substring(combinedData.length() - 24); // Last 24 characters are Base64-encoded random bytes

            System.out.println("Extracted User ID: " + userId);
            System.out.println("Extracted Random Bytes: " + randomBytesBase64);

            // Step 4: Verify the signature using the client's public key
            // COVERS BULLET POINT 2
            PublicKey clientPublicKey = loadPublicKey(userId + ".pub");
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(clientPublicKey);
            sig.update(Base64.getDecoder().decode(encryptedData));
            boolean isValid = sig.verify(Base64.getDecoder().decode(signature));
            
            // AUTHENTICATION FEEDBACK
            if (isValid) {
                System.out.println("Signature verified successfully.");
                out.writeUTF("Server: Authentication successful.");
            } else {
                System.out.println("Signature verification failed.");
                out.writeUTF("Server: Authentication failed.");
                return; // Terminate the connection if authentication fails
            }

            // TODO: Generate server's random bytes and send them back (Step 3)

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Error handling client request.");
        }
    }

    // Helper method to load the server's private key
    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(prvSpec);
    }

    // Helper method to load the client's public key
    private static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(pubSpec);
    }
}
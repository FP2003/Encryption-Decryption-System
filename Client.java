import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.util.Base64;

public class Client {
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: java Client <host> <port> <userid>");
            return;
        }

        String serverHost = args[0];
        int serverPort = Integer.parseInt(args[1]);
        String userId = args[2];

        try (Socket socket = new Socket(serverHost, serverPort);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            // Call firstServerCheck to get encrypted data and signature
            String[] result = firstServerCheck(userId);
            String encryptedData = result[0];
            String signature = result[1];

            // Send encrypted data and signature to the server
            out.writeUTF(encryptedData);
            out.writeUTF(signature);

            System.out.println("Sent encrypted data and signature to the server.");

            // Receive confirmation from server
            String serverResponse = in.readUTF();
            System.out.println("Server Response: " + serverResponse);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String[] firstServerCheck(String userId) throws Exception {
        
        // Generate 16 fresh random bytes
        // COVERS BULLET POINT 1
        byte[] randomBytes = new byte[16];
        new SecureRandom().nextBytes(randomBytes);

        // Combine userId and random bytes into a readable string
        // COVERS BULLET POINT 1
        String combinedData = userId + Base64.getEncoder().encodeToString(randomBytes);
        System.out.println("Combined Data: " + combinedData);

        // Convert combined data to bytes
        byte[] dataToEncrypt = combinedData.getBytes("UTF-8");

        // Load Server's public key (Server.pub)
        PublicKey serverPublicKey = loadPublicKey("Server.pub");
        // Load User's private key (Alice.prv)
        PrivateKey userPrivateKey = loadPrivateKey(userId + ".prv");

        // Encrypt the combined userId + random bytes using RSA
        // COVERS BULLET POINT 1
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedData = cipher.doFinal(dataToEncrypt);

        // Sign the encrypted data using SHA1withRSA
        // COVERS BULLET POINT 1
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(userPrivateKey);
        signature.update(encryptedData);
        byte[] signedData = signature.sign();

        // Convert encrypted data and signature to Base64
        // COVERS BULLET POINT 1
        return new String[]{
            Base64.getEncoder().encodeToString(encryptedData),
            Base64.getEncoder().encodeToString(signedData)
        };
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

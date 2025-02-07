import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

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
             DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             Scanner scanner = new Scanner(System.in)) {

            // Send a basic authentication message (this will be replaced later)
            out.writeUTF("Hello, I'm a client with ID: " + userId);

            try {
                // Call firstServerCheck
                String[] result = firstServerCheck(userId);
                System.out.println("Encrypted Data (Base64): " + result[0]);
                System.out.println("Signature (Base64): " + result[1]);
            } catch (Exception e) {
                System.err.println("Error occurred in firstServerCheck: " + e.getMessage());
                e.printStackTrace();
            }
            

            String serverResponse = in.readUTF();
            System.out.println(serverResponse);

            // User interaction loop
            while (true) {
                System.out.print("Enter command (ls, get <filename>, bye): ");
                String command = scanner.nextLine();
                out.writeUTF(command);

                if (command.equals("bye")) {
                    System.out.println("Disconnected from server.");
                    break;
                } else if (command.equals("ls")) {
                    int fileCount = in.readInt();
                    System.out.println("Files on server:");
                    for (int i = 0; i < fileCount; i++) {
                        System.out.println(in.readUTF());
                    }
                } else if (command.startsWith("get ")) {
                    receiveFile(command.substring(4), in);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String[] firstServerCheck(String userId) throws Exception {
        // Generate 16 fresh random bytes
        byte[] randomBytes = new byte[16];
        new SecureRandom().nextBytes(randomBytes);

        // Convert random bytes to Base64
        String randomBytesBase64 = Base64.getEncoder().encodeToString(randomBytes);

        // Combine userId and random bytes into a readable string
        String combinedData = userId + randomBytesBase64;
        System.out.println("Combined Data: " + combinedData);

        // Convert combined data to bytes
        byte[] dataToEncrypt = combinedData.getBytes("UTF-8");

        // Load Server's public key (Server.pub)
        PublicKey serverPublicKey = loadPublicKey("Server.pub");

        // Encrypt the combined userId + random bytes using RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedData = cipher.doFinal(dataToEncrypt);

        // Load User's private key (Alice.prv)
        PrivateKey userPrivateKey = loadPrivateKey(userId + ".prv");

        // Sign the encrypted data using SHA1withRSA
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(userPrivateKey);
        signature.update(encryptedData);
        byte[] signedData = signature.sign();

        // Convert encrypted data and signature to Base64
        String encryptedDataBase64 = Base64.getEncoder().encodeToString(encryptedData);
        String signatureBase64 = Base64.getEncoder().encodeToString(signedData);

        // Return both encrypted data and signature
        return new String[]{encryptedDataBase64, signatureBase64};
    }
    

    private static PublicKey loadPublicKey(String filename) throws Exception {
        File keyFile = new File(filename);
        byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
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

    

    private static void receiveFile(String filename, DataInputStream in) throws IOException {
        int fileLength = in.readInt();
        if (fileLength == 0) {
            System.out.println("File not found on server.");
            return;
        }

        byte[] fileBytes = new byte[fileLength];
        in.readFully(fileBytes);
        Files.write(new File(filename).toPath(), fileBytes);
        System.out.println("File received and saved: " + filename);
    }
}

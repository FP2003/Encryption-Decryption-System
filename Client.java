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
        
        System.out.println("Connecting to server: " + serverHost + " on port: " + serverPort);
        System.out.println("User ID: " + userId);
        
        try (Socket socket = new Socket(serverHost, serverPort);
             DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             Scanner scanner = new Scanner(System.in)) {

            // Send a basic authentication message (this will be replaced later)
            out.writeUTF("Hello, I'm a client with ID: " + userId);
            
            // Call firstServerCheck right after sending the initial message
            try {
                firstServerCheck(userId);
            } catch (Exception e) {
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

    public static void firstServerCheck(String userId) throws Exception {
        System.out.println("Performing first server check for user: " + userId);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        File f = new File(userId + ".prv");
        //byte[] keyBytes = Files.readAllBytes(f.toPath());
        //PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(keyBytes);
        //KeyFactory kf = KeyFactory.getInstance("RSA");
        //PrivateKey prvKey = kf.generatePrivate(prvSpec);

        System.out.println("Performing first server check for user: " + userId);
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

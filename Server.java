import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;

public class Server {
    private static final int PORT = 12345;

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server is running on port " + PORT);

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

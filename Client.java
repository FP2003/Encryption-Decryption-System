import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.nio.file.Files;
import java.nio.file.Path;


public class Client {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 12345;

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             Scanner scanner = new Scanner(System.in)) {

            // Send a basic authentication message (this will be replaced later)
            out.writeUTF("Hello, I'm a client");
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

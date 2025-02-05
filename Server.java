import java.io.*;
import java.net.*;

public class Server {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Usage: java Server <port>");
            return;
        }

        int port = Integer.parseInt(args[0]);
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server is listening on port " + port);

        while (true) {
            Socket socket = serverSocket.accept();
            System.out.println("Client connected");

            // Handle client request
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            // Read message from client
            String clientMessage = in.readLine();
            System.out.println("Client says: " + clientMessage);

            // Send response to client
            out.println("Hello, client!");

            socket.close();
        }
    }
}

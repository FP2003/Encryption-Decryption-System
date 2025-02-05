import java.io.*;
import java.net.*;

public class Client {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Usage: java Client <host> <port> <userid>");
            return;
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2];

        Socket socket = new Socket(host, port);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        // Send message to server
        out.println("Hello, server!");

        // Receive response from server
        String serverResponse = in.readLine();
        System.out.println("Server says: " + serverResponse);

        socket.close();
    }
}
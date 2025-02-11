import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec; //This line was not in the example
import java.security.spec.X509EncodedKeySpec; //This line was not in the example
import java.nio.file.Files;

// Copied from Lab 4, Exercise 2 solutions.
public class SigExample {

	public static void main(String [] args) throws Exception {

		// Get private key to create the signature
		File f = new File("alice.prv");
		byte[] keyBytes = Files.readAllBytes(f.toPath());
		PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey prvKey = kf.generatePrivate(prvSpec);

		// create signature
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(prvKey);
		sig.update("Hello world".getBytes());
		byte[] signature = sig.sign();
		
		// prompt input
		System.out.println("Enter the message to be verified:");
		Scanner sc = new Scanner(System.in);
		String input = sc.nextLine();

		// read public key to verify signature
		f = new File("alice.pub");
		keyBytes = Files.readAllBytes(f.toPath());
		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
		kf = KeyFactory.getInstance("RSA");
		PublicKey pubKey = kf.generatePublic(pubSpec);

		// verify signature
		sig.initVerify(pubKey);
		sig.update(input.getBytes());
		boolean b = sig.verify(signature);
		if (b) System.out.println("Signature verified");
		else System.out.println("Signature not verified");

	}
}

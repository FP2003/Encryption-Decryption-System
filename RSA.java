//SHOWS HOW TO ENCRYPT AND DECRYPT MESSAGES, USES THE PUBLIC KEY I BELIEVE 

import java.io.*; //
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.file.*;

public class RSA {

	public static void main(String args[]) throws Exception {

		if (args.length != 1) usage();

		if (args[0].equals("-e")) {

			// read key
			
			File f = new File("Alice.pub");
			byte[] keyBytes = Files.readAllBytes(f.toPath());
			X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey pubKey = kf.generatePublic(pubSpec);

			// taking input
			System.out.println("Enter a message: ");
			Scanner sc = new Scanner(System.in);
			String msg = sc.nextLine();



			// encrypt
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] raw = cipher.doFinal(msg.getBytes("UTF8"));

			// write to file
			File file = new File("encrypted.msg");
			FileOutputStream fos = new FileOutputStream(file);
			fos.write(raw);
			fos.close();

		}
		else if (args[0].equals("-d")) {

			// read key
			File f = new File("Alice.prv");
			byte[] keyBytes = Files.readAllBytes(f.toPath());
			PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey prvKey = kf.generatePrivate(prvSpec);

			// read file
			File file = new File("encrypted.msg");
			byte[] raw = Files.readAllBytes(file.toPath());

			// decrypt
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, prvKey);
			byte[] stringBytes = cipher.doFinal(raw);
			String result = new String(stringBytes, "UTF8");
			System.out.println(result);
		}

		else usage();
	}

	private static void usage() {
		System.out.println("Usage: java RSA -e|-d");
		System.exit(0);
	}

}

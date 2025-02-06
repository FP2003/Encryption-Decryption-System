import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.nio.file.Files;

public class ReadRSAKeys {

	public static void main(String [] args) throws Exception {

		File f = new File("Alice.prv");
		byte[] keyBytes = Files.readAllBytes(f.toPath());
		PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey prvKey = kf.generatePrivate(prvSpec);

		f = new File("alice.pub");
		keyBytes = Files.readAllBytes(f.toPath());
		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
		kf = KeyFactory.getInstance("RSA");
		PublicKey pubKey = kf.generatePublic(pubSpec);

		System.out.println(pubKey);
		System.out.println(prvKey);

	}
}
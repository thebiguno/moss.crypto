package ca.digitalcave.moss.crypto;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A utility class to simplify the Java encryption API.  This gives you the following abilities:
 *  1) Generate fully encapsulated cipher text for pre-existing key
 * 		Cipher text Format: "algorithmId:IV:cipherText"
 *  2) Generate fully encapsulated cipher text for keys generated from a password
 * 		Cipher text Format: "iterations:salt:algorithmId:IV:cipherText"
 *  3) Generate keys from a password
 *  4) Decrypt the encapsulated cipher text using either password or key (depending on which of the encryption methods was used)
 * 
 * @author wyatt
 *
 */
public class Crypto {
	private String rngAlgorithm = "SHA1PRNG";
	private Algorithm algorithm = Algorithm.AES_128;
	private int keySaltLength = 16;
	private int keyIterations = 1;

	public static void main(String[] args) throws Exception {
		for (Provider provider : Security.getProviders()){
			for (Provider.Service s : provider.getServices()){
				System.out.println(provider.getName() + " - " + s.getType() + ":" + s.getAlgorithm());
				
			}
		}
		
		Crypto crypto = new Crypto();
		crypto.setAlgorithm(Algorithm.DESede_168);
		System.out.println(crypto.encrypt("secretsu", "Foobar"));
		System.out.println(crypto.encrypt("secretsu", "Foobar"));
		System.out.println(crypto.encrypt("secretsu", "Foobar"));
		System.out.println(decrypt("secretsu", crypto.encrypt("secretsu", "Foobar")));
		
		final Key key = crypto.generateKey("secretsu");
		System.out.println(crypto.encrypt(key, "Foobar"));
		System.out.println(crypto.encrypt(key, "Foobar"));
		System.out.println(crypto.encrypt(key, "Foobar"));
		System.out.println(crypto.encrypt(key, "Foobar"));
		System.out.println(decrypt(key, crypto.encrypt(key, "Foobar")));
	}
	
	private PBEKeySpec generateKeySpec(String password) throws CryptoException {
		return new PBEKeySpec(password.toCharArray(), getRandomSalt(), keyIterations, algorithm.keyLength);
	}
	
	public Key generateKey(String password) throws CryptoException {
		return recoverKey(algorithm, generateKeySpec(password));
	}
	
	public static Key recoverKey(Algorithm algorithm, PBEKeySpec keySpec) throws CryptoException {
		try {
			final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm.keyFactoryAlgorithm);
			final Key tmp = keyFactory.generateSecret(keySpec);
			return new SecretKeySpec(tmp.getEncoded(), algorithm.keyAlgorithm);
		} catch (InvalidKeySpecException e) {
			throw new CryptoException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e);
		}
	}
	
	/**
	 * Encrypts a value using an existing Key object.  The encrypted form includes the IV and the 
	 * encrypted value, as an encoded string, with colons separating the parts.
	 * @param key
	 * @param plainText
	 * @return
	 * @throws CryptoException
	 */
	public String encrypt(Key key, String plainText) throws CryptoException {
		if (plainText == null) return null;
		try {
			final Cipher c = Cipher.getInstance(algorithm.cipherAlgorithm);
			c.init(Cipher.ENCRYPT_MODE, key);
			final AlgorithmParameters p = c.getParameters();

			final byte[] iv = p == null ? new byte[0] : p.getParameterSpec(IvParameterSpec.class).getIV();
			final byte[] out = c.doFinal(plainText.getBytes("UTF-8"));

			final StringBuilder sb = new StringBuilder();
			sb.append(algorithm.id);
			sb.append(":");
			sb.append(Base64.encode(iv));
			sb.append(":");
			sb.append(Base64.encode(out));
			
			return sb.toString();
		}
		catch (Exception e){
			throw new CryptoException(e);
		}
	}
	
	/**
	 * Encrypts a value using a password.  The encrypted form includes the Algorithm, key length, 
	 * iteration count, sald, IV, and the encrypted value, as an encoded string, with colons 
	 * separating the parts.
	 * @param password
	 * @param plainText
	 * @return
	 * @throws CryptoException
	 */
	public String encrypt(String password, String plainText) throws CryptoException {
		if (plainText == null) return null;
		try {
			final PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), getRandomSalt(), keyIterations, algorithm.keyLength);
			final Key key = recoverKey(algorithm, keySpec);
			
			final StringBuilder sb = new StringBuilder();
			sb.append(keySpec.getIterationCount());
			sb.append(":");
			sb.append(Base64.encode(keySpec.getSalt()));
			sb.append(":");
			sb.append(encrypt(key, plainText));
			
			return sb.toString();
		}
		catch (Exception e){
			throw new CryptoException(e);
		}
	}

	public static String decrypt(Key key, String encrypted) throws CryptoException {
		if (encrypted == null) return null;
		String[] split = encrypted.split(":");
		if (split.length != 3) {
			throw new CryptoException("Invalid cyphertext");
		}

		final Algorithm algorithm = Algorithm.findById(Integer.parseInt(split[0]));
		final byte[] iv = Base64.decode(split[1]);
		final byte[] in = Base64.decode(split[2]);

		try {
			final Cipher c = Cipher.getInstance(algorithm.cipherAlgorithm);
			c.init(Cipher.DECRYPT_MODE, key, iv.length == 0 ? null : new IvParameterSpec(iv));
			return new String(c.doFinal(in), "UTF-8");
		}
		catch (Exception e){
			throw new CryptoException(e);
		}
	}
	
	public static String decrypt(String password, String value) throws CryptoException {
		if (value == null) return null;
		String[] split = value.split(":");
		if (split.length != 5) {
			throw new CryptoException("Invalid cyphertext");
		}
		
		final int iterations = Integer.parseInt(split[0]);
		final byte[] salt = Base64.decode(split[1]);
		final Algorithm algorithm = Algorithm.findById(Integer.parseInt(split[2]));

		// recover the iv
		final String iv = split[3];

		// recover the cyphertext
		final String in = split[4];

		try {
			final PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, algorithm.keyLength);
			return decrypt(recoverKey(algorithm, keySpec), algorithm.id + ":" + iv + ":" + in);
		}
		catch (Exception e){
			throw new CryptoException(e);
		}
	}

	private byte[] getRandomSalt() {
		final byte[] salt = new byte[keySaltLength];
		try {
			final SecureRandom r = SecureRandom.getInstance(rngAlgorithm);
			r.nextBytes(salt);
			return salt;
		}
		catch (NoSuchAlgorithmException e){
			throw new RuntimeException(e);
		}
	}
	





	public String getRngAlgorithm() {
		return rngAlgorithm;
	}

	public Crypto setRngAlgorithm(String rngAlgorithm) {
		this.rngAlgorithm = rngAlgorithm;
		return this;
	}

	public Algorithm getAlgorithm() {
		return algorithm;
	}
	
	public Crypto setAlgorithm(Algorithm algorithm) {
		this.algorithm = algorithm;
		return this;
	}

	public int getKeySaltLength() {
		return keySaltLength;
	}

	public Crypto setKeySaltLength(int saltLength) {
		this.keySaltLength = saltLength;
		return this;
	}

	public int getKeyIterations() {
		return keyIterations;
	}

	public Crypto setKeyIterations(int iterations) {
		this.keyIterations = iterations;
		return this;
	}

	public enum Algorithm {
		AES_128(0, "PBKDF2WithHmacSHA1", "AES", "AES/CBC/PKCS5Padding", 128),
		AES_256(1, "PBKDF2WithHmacSHA1", "AES", "AES/CBC/PKCS5Padding", 256),
		DES_56(2, "PBEWithMD5AndDES", "DES", "DES/CBC/PKCS5Padding", 56),			//The password for the keyspec must be exactly 8 characters long for this algorithm
		DESede_168(3, "PBEWithSHA1AndDESede", "DESede", "DESede/CBC/PKCS5Padding", 168);

		public final int id;
		public final String keyFactoryAlgorithm;
		public final String keyAlgorithm;
		public final String cipherAlgorithm;
		public final int keyLength;
		
		private Algorithm(int id, String keyFactoryAlgorithm, String keyAlgorithm, String cipherAlgorithm, int keyLength) {
			this.id = id;
			this.keyFactoryAlgorithm = keyFactoryAlgorithm;
			this.keyAlgorithm = keyAlgorithm;
			this.cipherAlgorithm = cipherAlgorithm;
			this.keyLength = keyLength;
		}
		
		public static Algorithm findById(int id) throws CryptoException {
			for (Algorithm algorithm : Algorithm.values()) {
				if (id == algorithm.id) return algorithm;
			}
			throw new CryptoException("Unknown algorithm ID " + id);
		}
	}
	
	public static class CryptoException extends Exception {
		private static final long serialVersionUID = 1L;
		public CryptoException() {}
		public CryptoException(String message){
			super(message);
		}
		public CryptoException(Throwable throwable){
			super(throwable);
		}
		public CryptoException(String message, Throwable throwable){
			super(message, throwable);
		}
	}
}

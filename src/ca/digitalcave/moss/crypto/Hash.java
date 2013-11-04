package ca.digitalcave.moss.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Hash {
	
	private String rngAlgorithm = "SHA1PRNG";
	private String algorithm = "SHA-256";
	private int saltLength = 16;
	private int iterations = 1;
	
	/**
	 * Returns a string in the format "algorithm:iterations:salt:hash".
	 */
	public String generateHash(String message) {
		return generateHash(getRandomSalt(), message);
	}
	
	private String generateHash(byte[] salt, String message) {
		try {
			final MessageDigest digest = MessageDigest.getInstance(algorithm);
			final byte[] messageBytes = message.getBytes();
			
			digest.update(messageBytes);
			digest.update(salt);

			for (int i = 0; i < iterations; i++) {
				digest.update(digest.digest());
				digest.update(messageBytes);
				digest.update(salt);
			}

			final StringBuilder sb = new StringBuilder();
			sb.append(algorithm);
			sb.append(":");
			sb.append(Integer.toString(iterations, 16));
			sb.append(":");
			sb.append(Base64.encode(salt));
			sb.append(":");
			sb.append(Base64.encode(digest.digest()));
			return sb.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static boolean verifyHash(String hash, String message) {
		final int a = hash.indexOf(':');
		final int b = hash.indexOf(':', a + 1);
		final int c = hash.indexOf(':', b + 1);
		final String algorithm = hash.substring(0, a);
		final int iterations = Integer.parseInt(hash.substring(a + 1, b), 16);
		final byte[] salt = Base64.decode(hash.substring(b + 1, c));
		final String calc = new Hash().setAlgorithm(algorithm).setIterations(iterations).generateHash(salt, message);
		return hash.equalsIgnoreCase(calc);
	}
	
	private byte[] getRandomSalt() {
		final byte[] salt = new byte[saltLength];
		try {
			final SecureRandom r = SecureRandom.getInstance(rngAlgorithm);
			r.nextBytes(salt);
			return salt;
		}
		catch (NoSuchAlgorithmException e){
			throw new RuntimeException(e);
		}
	}

	public String getAlgorithm() {
		return algorithm;
	}
	public Hash setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
		return this;
	}
	
	public int getIterations() {
		return iterations;
	}
	public Hash setIterations(int iterations) {
		this.iterations = iterations;
		return this;
	}
	
	public int getSaltLength() {
		return saltLength;
	}
	public Hash setSaltLength(int saltLength) {
		this.saltLength = saltLength;
		return this;
	}
	
	public String getRngAlgorithm() {
		return rngAlgorithm;
	}
	public Hash setRngAlgorithm(String rngAlgorithm) {
		this.rngAlgorithm = rngAlgorithm;
		return this;
	}
}

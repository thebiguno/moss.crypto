package ca.digitalcave.moss.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtil {
	
	private static final int DEFAULT_ITERATIONS = 1;
	private static final int DEFAULT_SALT_LENGTH = 32;
	
	public static String generateSha256Hash(String message) {
		return generateSha256Hash(DEFAULT_ITERATIONS, CryptoUtil.getSecureRandom(DEFAULT_SALT_LENGTH), message);
	}

	public static String generateSha256Hash(int iterations, byte[] salt, String message) {
		return generateHash("SHA-256", iterations, salt, message);
	}
	
	/**
	 * Returns a string in the format "algorithm:iterations:salt:hash".
	 */
	public static String generateHash(String algorithm, int iterations, byte[] salt, String message) {
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
			sb.append(EncodeUtil.encode(salt));
			sb.append(":");
			sb.append(EncodeUtil.encode(digest.digest()));
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
		final byte[] salt = EncodeUtil.decode(hash.substring(b + 1, c));
		final String calc = generateHash(algorithm, iterations, salt, message);
		return hash.equalsIgnoreCase(calc);
	}
}

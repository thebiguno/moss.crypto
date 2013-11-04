package ca.digitalcave.moss.crypto;

import java.io.ByteArrayOutputStream;

public class Base64 {

	private static final String BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	public static void main(String[] args) {
		System.out.println(encode("foo".getBytes()));
		System.out.println(encode("foo1".getBytes()));
		System.out.println(encode("foo12".getBytes()));
		System.out.println(new String(decode(encode("foo".getBytes()))));
		System.out.println(new String(decode(encode("foo1".getBytes()))));
		System.out.println(new String(decode(encode("foo12".getBytes()))));
		System.out.println(encode("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes()));
		System.out.println(new String(decode(encode("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes()))));
	}
	
	
	public static String encode(final byte[] raw) {
		return encode(raw, false);
	}
	public static String encode(final byte[] raw, boolean newlines) {
		final StringBuilder result = new StringBuilder();
		final String padding;
		final byte[] padded;
		
		// add padding so that the length of the input is divisible by 3
		switch (raw.length % 3) {
		case 1:
			padding = "=="; 
			padded = new byte[raw.length + 2]; 
			System.arraycopy(raw, 0, padded, 0, raw.length);
			break;
		case 2: 
			padding = "=";
			padded = new byte[raw.length + 1];
			System.arraycopy(raw, 0, padded, 0, raw.length);
			break;
		default:
			padding = "";
			padded = raw;
			break;
		}

		// increment over the length of the string, three characters at a time
		for (int i = 0; i < padded.length; i += 3) {

			if (newlines) {
				// add newlines after every 76 output characters, according to the MIME specs
				if (i > 0 && (i / 3 * 4) % 76 == 0) result.append("\r\n");
			}

			// these three 8-bit (ASCII) characters become one 24-bit number
			int n = (padded[i] << 16) + (padded[i + 1] << 8) + (padded[i + 2]);

			// this 24-bit number gets separated into four 6-bit numbers
			int n1 = (n >> 18) & 63, n2 = (n >> 12) & 63, n3 = (n >> 6) & 63, n4 = n & 63;

			// those four 6-bit numbers are used as indices into the base64 character list
			result.append(BASE64_CHARS.charAt(n1));
			result.append(BASE64_CHARS.charAt(n2));
			result.append(BASE64_CHARS.charAt(n3));
			result.append(BASE64_CHARS.charAt(n4));
		}

		result.replace(result.length() - padding.length(), result.length(), padding);
		return result.toString();
	}
	public static byte[] decode(String encoded) {
		final ByteArrayOutputStream result = new ByteArrayOutputStream();
		// remove/ignore any characters not in the base64 characters list
		// or the pad character -- particularly newlines
		encoded = encoded.replaceAll("[^" + BASE64_CHARS + "=]", "");

		// replace any incoming padding with a zero pad (the 'A' character is zero)
		final String p = (encoded.charAt(encoded.length() - 1) == '=' ? 
				(encoded.charAt(encoded.length() - 2) == '=' ? "AA" : "A") : "");
		encoded = encoded.substring(0, encoded.length() - p.length()) + p;

		// increment over the length of this encrypted string, four characters
		// at a time
		for (int c = 0; c < encoded.length(); c += 4) {

			// each of these four characters represents a 6-bit index in the
			// base64 characters list which, when concatenated, will give the
			// 24-bit number for the original 3 characters
			int n = (BASE64_CHARS.indexOf(encoded.charAt(c)) << 18)
					+ (BASE64_CHARS.indexOf(encoded.charAt(c + 1)) << 12)
					+ (BASE64_CHARS.indexOf(encoded.charAt(c + 2)) << 6)
					+ BASE64_CHARS.indexOf(encoded.charAt(c + 3));

			// split the 24-bit number into the original three 8-bit (ASCII)
			// characters
			result.write(((n >>> 16) & 0xFF));
			result.write(((n >>> 8) & 0xFF));
			result.write(n & 0xFF);
		}

		// remove any zero pad that was added to make this a multiple of 24 bits
		return result.toByteArray();
	}
}

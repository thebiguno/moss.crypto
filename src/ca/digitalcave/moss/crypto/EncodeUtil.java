package ca.digitalcave.moss.crypto;

import org.restlet.engine.util.Base64;

public class EncodeUtil {

	public static String encode(byte[] bytes) {
		return Base64.encode(bytes, false);
	}

	public static byte[] decode(String encoded) {
		return Base64.decode(encoded);
	}
}

package it.auties.curve25519.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha512 {
    public static void calculateDigest(byte[] out, byte[] in, long length) {
        try {
            var messageDigest = MessageDigest.getInstance("SHA-512");
            messageDigest.update(in, 0, (int) length);
            var digest = messageDigest.digest();
            System.arraycopy(digest, 0, out, 0, digest.length);
        } catch (NoSuchAlgorithmException exception) {
            throw new UnsupportedOperationException("Missing SHA512 implementation", exception);
        }
    }
}

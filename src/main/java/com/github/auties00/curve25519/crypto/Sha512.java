package com.github.auties00.curve25519.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha512 {
    public static void calculateDigest(byte[] out, byte[] in, int offset, int length) {
        try {
            var messageDigest = MessageDigest.getInstance("SHA-512");
            messageDigest.update(in, offset, length);
            var digest = messageDigest.digest();
            System.arraycopy(digest, 0, out, 0, digest.length);
        } catch (NoSuchAlgorithmException exception) {
            throw new UnsupportedOperationException("Missing SHA512 implementation", exception);
        }
    }
}

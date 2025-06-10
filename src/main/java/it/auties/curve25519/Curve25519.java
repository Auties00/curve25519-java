/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 * <p>
 * Licensed according to the LICENSE file in this repository.
 */

package it.auties.curve25519;

import it.auties.curve25519.crypto.curve_sigs;
import it.auties.curve25519.crypto.scalarmult;

import java.security.*;
import java.util.Objects;

/**
 * Utility class to create a Curve25519 key pair, public key, private key, secret or signature
 */
@SuppressWarnings({"unused"})
public class Curve25519 {
    /**
     * The name of the algorithm used for Curve25519
     */
    private static final String KEY_ALGORITHM = "X25519";

    /**
     * The length of a Curve25519 key, whether public or private
     */
    private static final int KEY_LENGTH = 32;

    /**
     * The length of a Curve25519 signature
     */
    private static final int SIGNATURE_LENGTH = 64;

    /**
     * Generates a random private key
     *
     * @return A 32-byte Curve25519 private key
     */
    public static byte[] randomPrivateKey() {
        try {
            var privateKey = new byte[KEY_LENGTH];
            SecureRandom.getInstanceStrong()
                    .nextBytes(privateKey);
            privateKey[0] &= (byte) 248;
            privateKey[31] &= 127;
            privateKey[31] |= 64;
            return privateKey;
        }catch (GeneralSecurityException exception) {
            throw new RuntimeException("Cannot generate Curve25519 private key", exception);
        }
    }

    /**
     * Generates a public key from a private one
     *
     * @param privateKey the 32-byte Curve25519 private key
     * @return A 32-byte Curve25519 public key
     */
    public static byte[] getPublicKey(byte[] privateKey) {
        var publicKey = new byte[KEY_LENGTH];
        curve_sigs.curve25519_keygen(publicKey, 0, privateKey);
        return publicKey;
    }

    /**
     * Generates a public key from a private one
     *
     * @param privateKey the 32-byte Curve25519 private key
     * @param output the output buffer
     * @param offset the offset for the output buffer
     * @return A 32-byte Curve25519 public key
     */
    public static byte[] getPublicKey(byte[] privateKey, byte[] output, int offset) {
        curve_sigs.curve25519_keygen(output, offset, privateKey);
        return output;
    }

    /**
     * Calculates a Curve25519 shared key.
     *
     * @param publicKey The Curve25519 (typically remote party's) public key.
     * @param privateKey The Curve25519 (typically yours) private key.
     * @return A 32-byte shared secret.
     */
    public static byte[] sharedKey(byte[] publicKey, byte[] privateKey) {
        checkKey(publicKey);
        checkKey(privateKey);
        var agreement = new byte[KEY_LENGTH];
        scalarmult.crypto_scalarmult(agreement, 0, privateKey, publicKey);
        return agreement;
    }

    /**
     * Calculates a Curve25519 shared key.
     *
     * @param publicKey The Curve25519 (typically remote party's) public key.
     * @param privateKey The Curve25519 (typically yours) private key.
     * @param output the output buffer
     * @param offset the offset for the output buffer
     */
    public static void sharedKey(byte[] publicKey, byte[] privateKey, byte[] output, int offset) {
        checkKey(publicKey);
        checkKey(privateKey);
        scalarmult.crypto_scalarmult(output, offset, privateKey, publicKey);
    }

    /**
     * Calculates a Curve25519 signature.
     *
     * @param privateKey The private Curve25519 key to create the signature with.
     * @param message The message to sign.
     * @return A 64-byte signature.
     */
    public static byte[] sign(byte[] privateKey, byte[] message) {
        return sign(privateKey, message, null);
    }

    /**
     * Calculates a Curve25519 signature.
     *
     * @param privateKey The private Curve25519 key to create the signature with.
     * @param message The message to sign.
     * @param hash    Random nullable hash to make signature non-deterministic, can be generated using {@link Curve25519#randomSignatureHash()}.
     * @return A 64-byte signature.
     */
    public static byte[] sign(byte[] privateKey, byte[] message, byte[] hash) {
        checkKey(privateKey);
        checkHash(hash);
        var signature = new byte[SIGNATURE_LENGTH];
        curve_sigs.curve25519_sign(signature, 0, privateKey, message, message.length, hash);
        return signature;
    }

    /**
     * Calculates a Curve25519 signature.
     *
     * @param privateKey The private Curve25519 key to create the signature with.
     * @param message The message to sign.
     * @param messageLength The length of the message to sign.
     * @param hash    Random nullable hash to make signature non-deterministic, can be generated using {@link Curve25519#randomSignatureHash()}.
     * @param output the output buffer
     * @param offset the offset for the output buffer
     */
    public static void sign(byte[] privateKey, byte[] message, int messageLength, byte[] hash, byte[] output, int offset) {
        checkKey(privateKey);
        checkHash(hash);
        if (curve_sigs.curve25519_sign(output, offset, privateKey, message, messageLength, hash) != 0) {
            throw new IllegalArgumentException("Message exceeds max length!");
        }
    }

    /**
     * Generates a hash for {@link Curve25519#sign(byte[], byte[], byte[])} or {@link Curve25519#sign(byte[], byte[], int, byte[], byte[], int)}.
     *
     * @return a 64-byte random hash
     */
    public static byte[] randomSignatureHash() {
        try {
            var random = new byte[SIGNATURE_LENGTH];
            SecureRandom.getInstanceStrong()
                    .nextBytes(random);
            return random;
        }catch (GeneralSecurityException exception) {
            throw new RuntimeException("Cannot generate signature hash", exception);
        }
    }

    /**
     * Verify a Curve25519 signature.
     *
     * @param publicKey The Curve25519 public key the signature belongs to.
     * @param signature The signature to verify.
     * @return true if valid, false if not.
     */
    public static boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature) {
        return verifySignature(publicKey, message, message.length, signature);
    }

    /**
     * Verify a Curve25519 signature.
     *
     * @param publicKey The Curve25519 public key the signature belongs to.
     * @param message The message that was signed.
     * @param messageLength The length of the message that was signed.
     * @param signature The signature to verify.
     * @return true if valid, false if not.
     */
    public static boolean verifySignature(byte[] publicKey, byte[] message, int messageLength, byte[] signature) {
        checkKey(publicKey);
        return message != null
                && signature != null
                && signature.length == SIGNATURE_LENGTH
                && curve_sigs.curve25519_verify(signature, publicKey, message, messageLength) == 0;
    }

    private static void checkKey(byte[] key) {
        Objects.requireNonNull(key, "Key cannot be null!");
        if (key.length != KEY_LENGTH) {
            throw new IllegalArgumentException(String.format("Invalid key length: expected %s, got %s", KEY_LENGTH, key.length));
        }
    }

    private static void checkHash(byte[] hash) {
        if (hash != null && hash.length != SIGNATURE_LENGTH) {
            throw new IllegalArgumentException(String.format("Invalid hash length: expected %s, got %s", SIGNATURE_LENGTH, hash.length));
        }
    }
}

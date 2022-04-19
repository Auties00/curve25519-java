/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 * <p>
 * Licensed according to the LICENSE file in this repository.
 */

package it.auties.curve25519;

import it.auties.curve25519.crypto.curve_sigs;
import it.auties.curve25519.crypto.scalarmult;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.util.Objects;

import static it.auties.curve25519.XecUtils.toBytes;

/**
 * Utility class to create a Curve25519 key pair, public key, private key, secret or signature
 */
public class Curve25519 {
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
    public static XECPrivateKey randomPrivateKey() {
        var random = new SecureRandom();
        var rawPrivateKey = new byte[KEY_LENGTH];
        random.nextBytes(rawPrivateKey);
        rawPrivateKey[0]  &= 248;
        rawPrivateKey[31] &= 127;
        rawPrivateKey[31] |= 64;
        return XecUtils.toPrivateKey(rawPrivateKey);
    }


    /**
     * Generates a public key from a private one
     *
     * @param privateKey the 32-byte Curve25519 private key
     * @return A 32-byte Curve25519 public key
     */
    public static XECPublicKey forPrivateKey(PrivateKey privateKey) {
        if(!(privateKey instanceof XECPrivateKey)){
            throw new IllegalArgumentException("Invalid key type!");
        }

        return forPrivateKey(toBytes((XECPrivateKey) privateKey));
    }

    /**
     * Generates a public key from a private one
     *
     * @param privateKey the 32-byte Curve25519 private key
     * @return A 32-byte Curve25519 public key
     */
    public static XECPublicKey forPrivateKey(byte[] privateKey) {
        var rawPublicKey = new byte[KEY_LENGTH];
        curve_sigs.curve25519_keygen(rawPublicKey, privateKey);
        return XecUtils.toPublicKey(rawPublicKey);
    }

    /**
     * Generates a random Curve25519 keypair
     *
     * @return A Curve25519 keypair
     */
    public static KeyPair randomKeyPair() {
        var privateKey = randomPrivateKey();
        var publicKey = forPrivateKey(privateKey);
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Calculates an ECDH agreement.
     *
     * @param keyPair The Curve25519 keypair
     * @return A 32-byte shared secret.
     */
    public static byte[] sharedKey(KeyPair keyPair) {
        Objects.requireNonNull(keyPair, "Key pair cannot be null!");
        return sharedKey(keyPair.getPublic(), keyPair.getPrivate());
    }

    /**
     * Calculates an ECDH agreement.
     *
     * @param publicKey The Curve25519 (typically remote party's) public key.
     * @param privateKey The Curve25519 (typically yours) private key.
     * @return A 32-byte shared secret.
     */
    public static byte[] sharedKey(PublicKey publicKey, PrivateKey privateKey) {
        if (!(publicKey instanceof XECPublicKey) || !(privateKey instanceof XECPrivateKey)) {
            throw new IllegalArgumentException("Invalid key type!");
        }

        return sharedKey(toBytes((XECPublicKey) publicKey), toBytes((XECPrivateKey) privateKey));
    }

    /**
     * Calculates an ECDH agreement.
     *
     * @param publicKey The Curve25519 (typically remote party's) public key.
     * @param privateKey The Curve25519 (typically yours) private key.
     * @return A 32-byte shared secret.
     */
    public static byte[] sharedKey(PublicKey publicKey, byte[] privateKey) {
        if (!(publicKey instanceof XECPublicKey)) {
            throw new IllegalArgumentException("Invalid key type!");
        }

        return sharedKey(toBytes((XECPublicKey) publicKey), privateKey);
    }

    /**
     * Calculates an ECDH agreement.
     *
     * @param publicKey The Curve25519 (typically remote party's) public key.
     * @param privateKey The Curve25519 (typically yours) private key.
     * @return A 32-byte shared secret.
     */
    public static byte[] sharedKey(byte[] publicKey, PrivateKey privateKey) {
        if (!(privateKey instanceof XECPrivateKey)) {
            throw new IllegalArgumentException("Invalid key type!");
        }

        return sharedKey(publicKey, toBytes((XECPrivateKey) privateKey));
    }

    /**
     * Calculates an ECDH agreement.
     *
     * @param publicKey The Curve25519 (typically remote party's) public key.
     * @param privateKey The Curve25519 (typically yours) private key.
     * @return A 32-byte shared secret.
     */
    public static byte[] sharedKey(byte[] publicKey, byte[] privateKey) {
        checkKey(publicKey);
        checkKey(privateKey);
        var agreement = new byte[KEY_LENGTH];
        scalarmult.crypto_scalarmult(agreement, privateKey, publicKey);
        return agreement;
    }

    /**
     * Calculates a Curve25519 signature.
     *
     * @param keyPair The Curve25519 keypair to create the signature with, only the private key is used.
     * @param message The message to sign.
     * @param deterministic Whether the signature is deterministic or not. In other words if the hash is null or pseudorandom.
     * @return A 64-byte signature.
     */
    public static byte[] sign(KeyPair keyPair, byte[] message, boolean deterministic) {
        return sign(keyPair, message, randomSignatureHash(deterministic));
    }

    /**
     * Calculates a Curve25519 signature.
     *
     * @param keyPair The Curve25519 keypair to create the signature with, only the private key is used.
     * @param message The message to sign.
     * @param hash    Random hash to make signature non-deterministic.
     * @return A 64-byte signature.
     */
    public static byte[] sign(KeyPair keyPair, byte[] message, byte[] hash) {
        Objects.requireNonNull(keyPair, "Key pair cannot be null!");
        return sign(keyPair.getPrivate(), message, hash);
    }

    /**
     * Calculates a Curve25519 signature.
     *
     * @param privateKey The private Curve25519 key to create the signature with.
     * @param message The message to sign.
     * @param deterministic Whether the signature is deterministic or not. In other words if the hash is null or pseudorandom.
     * @return A 64-byte signature.
     */
    public static byte[] sign(PrivateKey privateKey, byte[] message, boolean deterministic) {
        return sign(privateKey, message, randomSignatureHash(deterministic));
    }


    /**
     * Calculates a Curve25519 signature.
     *
     * @param privateKey The private Curve25519 key to create the signature with.
     * @param message The message to sign.
     * @param hash    Random hash to make signature non-deterministic.
     * @return A 64-byte signature.
     */
    public static byte[] sign(PrivateKey privateKey, byte[] message, byte[] hash) {
        if (!(privateKey instanceof XECPrivateKey)) {
            throw new IllegalArgumentException("Invalid private key type!");
        }

        return sign(toBytes((XECPrivateKey) privateKey), message, hash);
    }

    /**
     * Calculates a Curve25519 signature.
     *
     * @param privateKey The private Curve25519 key to create the signature with.
     * @param message The message to sign.
     * @param deterministic Whether the signature is deterministic or not. In other words if the hash is null or pseudorandom.
     * @return A 64-byte signature.
     */
    public static byte[] sign(byte[] privateKey, byte[] message, boolean deterministic) {
        return sign(privateKey, message, randomSignatureHash(deterministic));
    }

    /**
     * Calculates a Curve25519 signature.
     *
     * @param privateKey The private Curve25519 key to create the signature with.
     * @param message The message to sign.
     * @param hash    Random hash to make signature non-deterministic.
     * @return A 64-byte signature.
     */
    public static byte[] sign(byte[] privateKey, byte[] message, byte[] hash) {
        checkKey(privateKey);
        checkHash(hash);
        var signature = new byte[SIGNATURE_LENGTH];
        if (curve_sigs.curve25519_sign(signature, privateKey, message, message.length, hash) != 0) {
            throw new IllegalArgumentException("Message exceeds max length!");
        }

        return signature;
    }

    /**
     * Verify a Curve25519 signature.
     *
     * @param publicKey The Curve25519 public key the signature belongs to.
     * @param message The message that was signed.
     * @param signature The signature to verify.
     * @return true if valid, false if not.
     */
    public static boolean verifySignature(PublicKey publicKey, byte[] message, byte[] signature) {
        if(!(publicKey instanceof XECPublicKey)){
            throw new IllegalArgumentException("Invalid key type!");
        }

        return verifySignature(toBytes((XECPublicKey) publicKey), message, signature);
    }

    /**
     * Verify a Curve25519 signature.
     *
     * @param publicKey The Curve25519 public key the signature belongs to.
     * @param message The message that was signed.
     * @param signature The signature to verify.
     * @return true if valid, false if not.
     */
    public static boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature) {
        checkKey(publicKey);
        return message != null && signature != null && signature.length == SIGNATURE_LENGTH
                && curve_sigs.curve25519_verify(signature, publicKey, message, message.length) == 0;
    }

    private static byte[] randomSignatureHash(boolean deterministic) {
        if(deterministic){
            return null;
        }

        var random = new byte[SIGNATURE_LENGTH];
        new SecureRandom().nextBytes(random);
        return random;
    }

    private static void checkKey(byte[] key) {
        Objects.requireNonNull(key, "Key cannot be null!");
        if (key.length == KEY_LENGTH) {
            return;
        }

        throw new IllegalArgumentException(String.format("Invalid key length: expected %s, got %s", KEY_LENGTH, key.length));
    }

    private static void checkHash(byte[] hash) {
        if (hash == null || hash.length == SIGNATURE_LENGTH) {
            return;
        }

        throw new IllegalArgumentException(String.format("Invalid hash length: expected %s, got %s", SIGNATURE_LENGTH, hash.length));
    }
}

/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 * <p>
 * Licensed according to the LICENSE file in this repository.
 */

package it.auties.curve25519;

import it.auties.curve25519.crypto.curve_sigs;
import it.auties.curve25519.crypto.scalarmult;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.NoSuchElementException;
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
    public static XECPrivateKey randomPrivateKey() {
        var random = new SecureRandom();
        var rawPrivateKey = new byte[KEY_LENGTH];
        random.nextBytes(rawPrivateKey);
        rawPrivateKey[0] &= (byte) 248;
        rawPrivateKey[31] &= 127;
        rawPrivateKey[31] |= 64;
        return createPrivateKey(rawPrivateKey);
    }

    /**
     * Generates a random Curve25519 keypair
     *
     * @return A Curve25519 keypair
     */
    public static KeyPair randomKeyPair() {
        var privateKey = randomPrivateKey();
        var publicKey = getPublicKey(privateKey);
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
        checkPublicKeyType(publicKey);
        checkPrivateKeyType(privateKey);
        return sharedKey(readKey(publicKey), readKey(privateKey));
    }

    /**
     * Calculates an ECDH agreement.
     *
     * @param publicKey The Curve25519 (typically remote party's) public key.
     * @param privateKey The Curve25519 (typically yours) private key.
     * @return A 32-byte shared secret.
     */
    public static byte[] sharedKey(PublicKey publicKey, byte[] privateKey) {
        checkPublicKeyType(publicKey);
        return sharedKey(readKey(publicKey), privateKey);
    }

    /**
     * Calculates an ECDH agreement.
     *
     * @param publicKey The Curve25519 (typically remote party's) public key.
     * @param privateKey The Curve25519 (typically yours) private key.
     * @return A 32-byte shared secret.
     */
    public static byte[] sharedKey(byte[] publicKey, PrivateKey privateKey) {
        checkPrivateKeyType(privateKey);
        return sharedKey(publicKey, readKey(privateKey));
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
        checkPrivateKeyType(privateKey);
        return sign(readKey(privateKey), message, hash);
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
        checkPublicKeyType(publicKey);
        return verifySignature(readKey(publicKey), message, signature);
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

    /**
     * Generates a public key from a private one
     *
     * @param privateKey the 32-byte Curve25519 private key
     * @return A 32-byte Curve25519 public key
     */
    public static XECPublicKey getPublicKey(PrivateKey privateKey) {
        checkPrivateKeyType(privateKey);
        return getPublicKey(readKey(privateKey));
    }

    /**
     * Generates a public key from a private one
     *
     * @param privateKey the 32-byte Curve25519 private key
     * @return A 32-byte Curve25519 public key
     */
    public static XECPublicKey getPublicKey(byte[] privateKey) {
        var rawPublicKey = new byte[KEY_LENGTH];
        curve_sigs.curve25519_keygen(rawPublicKey, privateKey);
        return createPublicKey(rawPublicKey);
    }

    /**
     * Converts a raw public key to a XEC public key
     *
     * @param rawPublicKey the raw public key to convert
     * @return a non-null XECPublicKey
     */
    public static XECPublicKey createPublicKey(byte[] rawPublicKey){
        try {
            Objects.requireNonNull(rawPublicKey, "Public key cannot be null!");
            var keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            var xecPublicKeySpec = new XECPublicKeySpec(NamedParameterSpec.X25519, new BigInteger(convertKeyToJca(rawPublicKey)));
            return (XECPublicKey) keyFactory.generatePublic(xecPublicKeySpec);
        } catch (NoSuchAlgorithmException | ClassCastException exception) {
            throw new UnsupportedOperationException("Missing Curve25519 implementation", exception);
        } catch (InvalidKeySpecException exception) {
            throw new RuntimeException("Internal exception during key generation", exception);
        }
    }

    /**
     * Converts a raw private key to a XEC private key
     *
     * @param rawPrivateKey the raw private key to convert
     * @return a non-null XECPrivateKey
     */
    public static XECPrivateKey createPrivateKey(byte[] rawPrivateKey){
        try {
            Objects.requireNonNull(rawPrivateKey, "Private key cannot be null!");
            var keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            var xecPrivateKeySpec = new XECPrivateKeySpec(NamedParameterSpec.X25519, rawPrivateKey);
            return (XECPrivateKey) keyFactory.generatePrivate(xecPrivateKeySpec);
        } catch (NoSuchAlgorithmException | ClassCastException exception) {
            throw new UnsupportedOperationException("Missing Curve25519 implementation", exception);
        } catch (InvalidKeySpecException exception) {
            throw new RuntimeException("Internal exception during key generation", exception);
        }
    }

    /**
     * Converts the input public key in a raw public key
     *
     * @param publicKey the public key to convert
     * @return a non-null array of bytes
     */
    public static byte[] readKey(PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "Public key cannot be null!");
        checkPublicKeyType(publicKey);
        return convertKeyToJca(((XECPublicKey) publicKey).getU().toByteArray());
    }

    /**
     * Converts the input private key in a raw private key
     *
     * @param privateKey the private key to convert
     * @return a non-null array of bytes
     */
    public static byte[] readKey(PrivateKey privateKey) {
        Objects.requireNonNull(privateKey, "Private key cannot be null!");
        checkPrivateKeyType(privateKey);
        return ((XECPrivateKey) privateKey).getScalar()
                .orElseThrow(() -> new NoSuchElementException("Scalar content cannot be null!"));
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

    private static void checkPublicKeyType(PublicKey publicKey) {
        if (!(publicKey instanceof XECPublicKey)) {
            throw new IllegalArgumentException("Invalid key type!");
        }
    }

    private static void checkPrivateKeyType(PrivateKey privateKey) {
        if (!(privateKey instanceof XECPrivateKey)) {
            throw new IllegalArgumentException("Invalid key type!");
        }
    }

    // We need to copy the array because we can't modify the original one
    // So no zero copy implementation is possible
    private static byte[] convertKeyToJca(byte[] arr) {
        var result = new byte[KEY_LENGTH];
        var padding = result.length - arr.length;
        for(var i = 0; i < arr.length; i++) {
            result[i + padding] = arr[arr.length - (i + 1)];
        }

        return result;
    }
}

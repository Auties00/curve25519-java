
package com.github.auties00.curve25519;

import com.github.auties00.curve25519.crypto.curve_sigs;
import com.github.auties00.curve25519.crypto.gen_x;
import com.github.auties00.curve25519.crypto.scalarmult;

import java.security.*;
import java.util.Objects;

/**
 * A high-performance Java implementation of the Curve25519 elliptic curve cryptographic operations.
 *
 * <p>This utility class provides comprehensive support for:</p>
 * <ul>
 *   <li><strong>Key Generation:</strong> Creating secure private/public key pairs</li>
 *   <li><strong>Key Agreement:</strong> Elliptic Curve Diffie-Hellman (ECDH) shared secret computation</li>
 *   <li><strong>Digital Signatures:</strong> Ed25519 compatible signature creation and verification</li>
 *   <li><strong>Verifiable Random Functions (VRF):</strong> VEdDSA-based VRF signatures for cryptographic randomness with proofs</li>
 * </ul>
 *
 * <p><strong>Security Features:</strong></p>
 * <ul>
 *   <li>Side-channel attack resistant implementations</li>
 *   <li>Constant-time operations for critical cryptographic functions</li>
 *   <li>Proper key clamping and validation</li>
 *   <li>Secure random number generation using {@link SecureRandom#getInstanceStrong()}</li>
 * </ul>
 *
 * <p><strong>Performance:</strong> This implementation is optimized for performance while maintaining
 * cryptographic security, suitable for high-throughput applications.</p>
 *
 * <p><strong>Thread Safety:</strong> All methods in this class are thread-safe and stateless.</p>
 *
 * <p><strong>Exception Handling:</strong></p>
 * <ul>
 *   <li>{@link NullPointerException} - thrown when required parameters are null</li>
 *   <li>{@link IndexOutOfBoundsException} - thrown for invalid array lengths or buffer boundary violations</li>
 *   <li>{@link InternalError} - thrown when underlying cryptographic operations fail</li>
 *   <li>{@link SignatureException} - thrown when VRF signature verification fails</li>
 * </ul>
 *
 * <p><strong>Example Usage:</strong></p>
 * <pre>{@code
 * // Generate a key pair
 * byte[] privateKey = Curve25519.randomPrivateKey();
 * byte[] publicKey = Curve25519.getPublicKey(privateKey);
 *
 * // Create and verify a signature
 * byte[] message = "Hello, World!".getBytes();
 * byte[] signature = Curve25519.sign(privateKey, message);
 * boolean valid = Curve25519.verifySignature(publicKey, message, signature);
 *
 * // Compute shared secret (ECDH)
 * byte[] otherPrivateKey = Curve25519.randomPrivateKey();
 * byte[] otherPublicKey = Curve25519.getPublicKey(otherPrivateKey);
 * byte[] sharedSecret = Curve25519.sharedKey(privateKey, otherPublicKey);
 * }</pre>
 *
 * @author GitHub: auties00
 * @since 1.0.0
 */
@SuppressWarnings({"unused"})
public final class Curve25519 {
    /**
     * A secure random instance
     */
    private static final SecureRandom RANDOM;

    /**
     * The standard length in bytes for Curve25519 keys (both public and private).
     * This is a cryptographic constant defined by the Curve25519 specification.
     */
    private static final int KEY_LENGTH = 32;

    /**
     * The standard length in bytes for Ed25519 signatures.
     * Each signature consists of a 32-byte R value and a 32-byte S value.
     */
    private static final int SIGNATURE_LENGTH = 64;

    /**
     * The length in bytes for VEdDSA VRF signatures.
     * VRF signatures contain additional cryptographic proof data beyond standard signatures.
     */
    private static final int VRF_SIGNATURE_LENGTH = 96;

    /**
     * The length in bytes for VRF output values.
     * This represents the pseudorandom output that can be verified using the VRF proof.
     */
    private static final int VRF_LENGTH = 32;

    static {
        try {
            RANDOM = SecureRandom.getInstanceStrong();
        }catch (NoSuchAlgorithmException exception) {
            throw new InternalError("Cannot initialize Curve25519", exception);
        }
    }

    /**
     * Generates a cryptographically secure random private key for Curve25519.
     *
     * <p>The generated key is properly clamped according to the Curve25519 specification:</p>
     * <ul>
     *   <li>The lowest 3 bits are cleared (ensures multiple of 8)</li>
     *   <li>The highest bit is cleared (ensures positive scalar)</li>
     *   <li>The second-highest bit is set (ensures large scalar)</li>
     * </ul>
     *
     * <p><strong>Security:</strong> Uses {@link SecureRandom#getInstanceStrong()} for
     * cryptographically secure random number generation.</p>
     *
     * @return A 32-byte Curve25519 private key, properly formatted and clamped
     * @throws RuntimeException if the cryptographically strong random number generator
     *                         is not available on this platform
     * @see #getPublicKey(byte[])
     */
    public static byte[] randomPrivateKey() {
        var privateKey = new byte[KEY_LENGTH];
        RANDOM.nextBytes(privateKey);
        privateKey[0] &= (byte) 248;
        privateKey[31] &= 127;
        privateKey[31] |= 64;
        return privateKey;
    }

    /**
     * Derives a public key from the given private key using Curve25519 scalar multiplication.
     *
     * <p>This operation computes the scalar multiplication of the base point by the private key,
     * resulting in the corresponding public key point encoded in Montgomery form.</p>
     *
     * @param privateKey A 32-byte Curve25519 private key (must be properly clamped)
     * @return A 32-byte Curve25519 public key in Montgomery form
     * @throws NullPointerException if the private key is null
     * @throws IndexOutOfBoundsException if the private key is not exactly 32 bytes
     * @see #randomPrivateKey()
     */
    public static byte[] getPublicKey(byte[] privateKey) {
        var publicKey = new byte[KEY_LENGTH];
        curve_sigs.curve25519_keygen(
                publicKey,
                0,
                checkKey(privateKey, 0)
        );
        return publicKey;
    }

    /**
     * Derives a public key from the given private key and stores it in the specified output buffer.
     *
     * <p>This is a memory-efficient variant that writes directly to a provided buffer,
     * avoiding additional memory allocation.</p>
     *
     * @param privateKey A 32-byte Curve25519 private key
     * @param output The output buffer to store the public key
     * @param offset The starting position in the output buffer
     * @return The same output buffer that was passed in (for method chaining)
     * @throws NullPointerException if the private key or output buffer is null
     * @throws IndexOutOfBoundsException if the private key is invalid or buffer space is insufficient
     */
    public static byte[] getPublicKey(byte[] privateKey, byte[] output, int offset) {
        curve_sigs.curve25519_keygen(
                Objects.requireNonNull(output, "output cannot be null"),
                Objects.checkFromIndexSize(offset, KEY_LENGTH, output.length),
                checkKey(privateKey, 0)
        );
        return output;
    }

    /**
     * Computes a shared secret using Elliptic Curve Diffie-Hellman (ECDH) key agreement.
     *
     * <p>This method performs the core ECDH operation: multiplying the remote party's public key
     * by your private key to derive a shared secret that both parties can compute independently.</p>
     *
     * <p><strong>Security Considerations:</strong></p>
     * <ul>
     *   <li>The shared secret should be used with a key derivation function (KDF) before use</li>
     *   <li>Both parties will compute the same shared secret value</li>
     *   <li>The operation is constant-time to prevent timing attacks</li>
     * </ul>
     *
     * <p><strong>Example:</strong></p>
     * <pre>{@code
     * // Alice's side
     * byte[] alicePrivate = Curve25519.randomPrivateKey();
     * byte[] alicePublic = Curve25519.getPublicKey(alicePrivate);
     *
     * // Bob's side
     * byte[] bobPrivate = Curve25519.randomPrivateKey();
     * byte[] bobPublic = Curve25519.getPublicKey(bobPrivate);
     *
     * // Both compute the same shared secret
     * byte[] sharedSecretAlice = Curve25519.sharedKey(alicePrivate, bobPublic);
     * byte[] sharedSecretBob = Curve25519.sharedKey(bobPrivate, alicePublic);
     * // Arrays.equals(sharedSecretAlice, sharedSecretBob) == true
     * }</pre>
     *
     * @param privateKey Your 32-byte Curve25519 private key
     * @param publicKey The remote party's 32-byte Curve25519 public key
     * @return A 32-byte shared secret
     * @throws NullPointerException if either key is null
     * @throws IndexOutOfBoundsException if either key is not exactly 32 bytes
     * @throws InternalError if the underlying cryptographic operation fails
     */
    public static byte[] sharedKey(byte[] privateKey, byte[] publicKey) {
        var agreement = new byte[KEY_LENGTH];
        var result = scalarmult.crypto_scalarmult(
                agreement,
                0,
                checkKey(privateKey, 0),
                checkKey(publicKey, 0),
                0
        );
        if(result != 0) {
            throw new InternalError("crypto_scalarmult failed");
        }
        return agreement;
    }

    /**
     * Computes a shared secret and stores it in the specified output buffer.
     *
     * <p>This is a memory-efficient variant of {@link #sharedKey(byte[], byte[])} that
     * writes directly to a provided buffer.</p>
     *
     * @param privateKey Your 32-byte Curve25519 private key
     * @param publicKey The remote party's 32-byte Curve25519 public key
     * @param publicKeyOffset The starting position of the public key in its buffer
     * @param output The output buffer to store the shared secret
     * @param offset The starting position in the output buffer
     * @throws NullPointerException if any required buffer is null
     * @throws IndexOutOfBoundsException if any key is invalid or buffer boundaries are exceeded
     * @throws InternalError if the underlying cryptographic operation fails
     */
    public static void sharedKey(byte[] privateKey, byte[] publicKey, int publicKeyOffset, byte[] output, int offset) {
        var result = scalarmult.crypto_scalarmult(
                Objects.requireNonNull(output, "output cannot be null"),
                Objects.checkFromIndexSize(offset, KEY_LENGTH, output.length),
                checkKey(privateKey, 0),
                checkKey(publicKey, publicKeyOffset),
                publicKeyOffset
        );
        if(result != 0) {
            throw new InternalError("crypto_scalarmult failed");
        }
    }

    /**
     * Creates a digital signature for the specified message using Ed25519.
     *
     * <p>This method creates a deterministic signature by default. For non-deterministic
     * signatures, use {@link #sign(byte[], byte[], byte[])} with random data.</p>
     *
     * @param privateKey The 32-byte private key to sign with
     * @param message The message bytes to sign
     * @return A 64-byte Ed25519 signature
     * @throws NullPointerException if the private key or message is null
     * @throws IndexOutOfBoundsException if the private key is not exactly 32 bytes
     * @throws InternalError if the signature generation fails
     * @see #sign(byte[], byte[], byte[])
     * @see #verifySignature(byte[], byte[], byte[])
     */
    public static byte[] sign(byte[] privateKey, byte[] message) {
        return sign(privateKey, message, null);
    }

    /**
     * Creates a digital signature with optional randomization for enhanced security.
     *
     * <p><strong>Deterministic vs Non-deterministic Signatures:</strong></p>
     * <ul>
     *   <li><strong>Deterministic</strong> ({@code random = null}): Same message + key always produces the same signature</li>
     *   <li><strong>Non-deterministic</strong> ({@code random != null}): Each signature is unique, providing additional security against side-channel attacks</li>
     * </ul>
     *
     * <p><strong>Security Benefits of Randomization:</strong></p>
     * <ul>
     *   <li>Protection against fault injection attacks</li>
     *   <li>Enhanced resistance to side-channel analysis</li>
     *   <li>Signatures remain unlinkable even for identical messages</li>
     * </ul>
     *
     * @param privateKey The 32-byte private key to sign with
     * @param message The message bytes to sign
     * @param random Optional 64-byte random data for non-deterministic signatures,
     *               or {@code null} for deterministic signatures. Generate using {@link #randomSignatureData()}
     * @return A 64-byte Ed25519 signature
     * @throws NullPointerException if the private key or message is null
     * @throws IndexOutOfBoundsException if the private key is invalid or random data is wrong length
     * @throws InternalError if the signature generation fails
     * @see #randomSignatureData()
     * @see #verifySignature(byte[], byte[], byte[])
     */
    public static byte[] sign(byte[] privateKey, byte[] message, byte[] random) {
        var signature = new byte[SIGNATURE_LENGTH];
        var result = curve_sigs.curve25519_sign(
                signature,
                0,
                checkKey(privateKey, 0),
                Objects.requireNonNull(message, "message cannot be null"),
                0,
                message.length,
                checkSignatureRandom(random)
        );
        if(result != 0) {
            throw new InternalError("curve25519_sign failed");
        }
        return signature;
    }

    /**
     * Creates a digital signature with precise control over input parameters and output buffer.
     *
     * <p>This method provides maximum flexibility for performance-critical applications
     * by allowing direct buffer manipulation and partial message processing.</p>
     *
     * @param privateKey The 32-byte private key to sign with
     * @param message The message buffer containing data to sign
     * @param messageOffset The starting position of the message within the buffer
     * @param messageLength The number of bytes to sign from the message buffer
     * @param random Optional random data for non-deterministic signatures
     * @param output The output buffer to store the signature
     * @param offset The starting position in the output buffer
     * @throws NullPointerException if any required buffer is null
     * @throws IndexOutOfBoundsException if any parameter is invalid or buffer boundaries are exceeded
     * @throws InternalError if the signature generation fails
     */
    public static void sign(byte[] privateKey, byte[] message, int messageOffset, int messageLength, byte[] random, byte[] output, int offset) {
        var result = curve_sigs.curve25519_sign(
                Objects.requireNonNull(output, "output cannot be null"),
                Objects.checkFromIndexSize(offset, SIGNATURE_LENGTH, output.length),
                checkKey(privateKey, 0),
                Objects.requireNonNull(message, "message cannot be null"),
                Objects.checkFromIndexSize(messageOffset, messageLength, message.length),
                messageLength,
                random
        );
        if(result != 0) {
            throw new InternalError("curve25519_sign failed");
        }
    }

    /**
     * Generates cryptographically secure random data for non-deterministic signatures.
     *
     * <p>This random data should be used with {@link #sign(byte[], byte[], byte[])} to create
     * non-deterministic signatures that provide enhanced security properties.</p>
     *
     * <p><strong>Usage:</strong> The returned data is meant to be used once per signature
     * and should not be reused across multiple signing operations.</p>
     *
     * @return 64 bytes of cryptographically secure random data
     * @throws RuntimeException if the cryptographically strong random number generator
     *                         is not available on this platform
     * @see #sign(byte[], byte[], byte[])
     */
    public static byte[] randomSignatureData() {
        var random = new byte[SIGNATURE_LENGTH];
        RANDOM.nextBytes(random);
        return random;
    }

    /**
     * Verifies an Ed25519 digital signature against a message and public key.
     *
     * <p><strong>Constant-Time Operation:</strong> This verification is performed in constant time
     * to prevent timing-based side-channel attacks.</p>
     *
     * <p><strong>Example:</strong></p>
     * <pre>{@code
     * byte[] privateKey = Curve25519.randomPrivateKey();
     * byte[] publicKey = Curve25519.getPublicKey(privateKey);
     * byte[] message = "Important message".getBytes();
     *
     * // Sign and verify
     * byte[] signature = Curve25519.sign(privateKey, message);
     * boolean isValid = Curve25519.verifySignature(publicKey, message, signature);
     * assert isValid; // Should be true for valid signature
     * }</pre>
     *
     * @param publicKey The 32-byte public key corresponding to the signature
     * @param message The original message that was signed
     * @param signature The 64-byte signature to verify
     * @return {@code true} if the signature is valid and authentic, {@code false} otherwise
     * @throws NullPointerException if any parameter is null
     * @throws IndexOutOfBoundsException if any parameter has invalid length
     */
    public static boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature) {
        return verifySignature(publicKey, 0, Objects.requireNonNull(message, "message cannot be null"), 0, message.length, signature, 0);
    }

    /**
     * Verifies an Ed25519 digital signature with precise buffer control.
     *
     * <p>This method allows verification of signatures using data from specific positions
     * within larger buffers, useful for protocol implementations and performance optimization.</p>
     *
     * @param publicKey The buffer containing the public key
     * @param publicKeyOffset The starting position of the public key
     * @param message The buffer containing the signed message
     * @param messageOffset The starting position of the message
     * @param messageLength The number of bytes that were signed
     * @param signature The buffer containing the signature
     * @param signatureOffset The starting position of the signature
     * @return {@code true} if the signature is valid, {@code false} otherwise
     * @throws NullPointerException if any buffer is null
     * @throws IndexOutOfBoundsException if any key is invalid or buffer boundaries are exceeded
     */
    public static boolean verifySignature(byte[] publicKey, int publicKeyOffset, byte[] message, int messageOffset, int messageLength, byte[] signature, int signatureOffset) {
        var result = curve_sigs.curve25519_verify(
                Objects.requireNonNull(signature, "signature cannot be null"),
                Objects.checkFromIndexSize(signatureOffset, SIGNATURE_LENGTH, signature.length),
                checkKey(publicKey, publicKeyOffset),
                publicKeyOffset,
                Objects.requireNonNull(message, "message cannot be null"),
                Objects.checkFromIndexSize(messageOffset, messageLength, message.length),
                messageLength
        );
        return result == 0;
    }

    /**
     * Creates a Verifiable Random Function (VRF) signature using VEdDSA.
     *
     * <p>This method creates a deterministic signature by default. For non-deterministic
     * signatures, use {@link #signVrf(byte[], byte[], byte[])} with random data.</p>
     *
     * @param privateKey The 32-byte private key to sign with
     * @param message The message bytes to sign
     * @return A 64-byte Ed25519 signature
     * @throws NullPointerException if the private key or message is null
     * @throws IndexOutOfBoundsException if the private key is not exactly 32 bytes
     * @throws InternalError if the signature generation fails
     * @see #sign(byte[], byte[], byte[])
     * @see #verifySignature(byte[], byte[], byte[])
     */
    public static byte[] signVrf(byte[] privateKey, byte[] message) {
        return signVrf(privateKey, message, null);
    }

    /**
     * Creates a Verifiable Random Function (VRF) signature using VEdDSA.
     *
     * <p><strong>Verifiable Random Functions</strong> provide cryptographically verifiable randomness.
     * Unlike regular signatures, VRF signatures prove that the output was generated correctly
     * from the input without revealing the private key.</p>
     *
     * <p><strong>Use Cases:</strong></p>
     * <ul>
     *   <li>Cryptographic lotteries and random selection</li>
     *   <li>Consensus algorithms requiring verifiable randomness</li>
     *   <li>Blockchain applications needing unpredictable but verifiable values</li>
     * </ul>
     *
     * <p><strong>Security Properties:</strong></p>
     * <ul>
     *   <li><strong>Uniqueness:</strong> For any input and key, there's exactly one valid output</li>
     *   <li><strong>Pseudorandomness:</strong> Output appears random to those without the private key</li>
     *   <li><strong>Verifiability:</strong> Anyone can verify the output using the public key</li>
     * </ul>
     *
     * @param privateKey The 32-byte private key to create the VRF signature
     * @param message The input message for the VRF
     * @param random Optional random data for enhanced security (currently unused in this implementation)
     * @return A 96-byte VRF signature containing both the proof and necessary verification data
     * @throws NullPointerException if the private key or message is null
     * @throws IndexOutOfBoundsException if the private key is not exactly 32 bytes
     * @throws InternalError if VRF signature generation fails
     * @see #verifyVrfSignature(byte[], byte[], byte[])
     * @see #randomVrfSignatureData()
     */
    public static byte[] signVrf(byte[] privateKey, byte[] message, byte[] random) {
        var signature = new byte[VRF_SIGNATURE_LENGTH];
        var result = gen_x.generalized_xveddsa_25519_sign(
                signature,
                0,
                checkKey(privateKey, 0),
                Objects.requireNonNull(message, "message cannot be null"),
                0,
                message.length,
                checkVrfSignatureRandom(random)
        );
        if(!result) {
            throw new InternalError("generalized_xveddsa_25519_sign failed");
        }
        return signature;
    }

    /**
     * Creates a VRF signature with precise buffer control for high-performance applications.
     *
     * <p>This method provides direct buffer manipulation capabilities for applications
     * requiring maximum performance or integration with existing buffer management systems.</p>
     *
     * @param privateKey The 32-byte private key
     * @param message The message buffer
     * @param messageOffset Starting position of the message
     * @param messageLength Number of bytes to process
     * @param random Optional random data (currently unused)
     * @param output Buffer to store the 96-byte VRF signature
     * @param offset Starting position in the output buffer
     * @throws NullPointerException if any required buffer is null
     * @throws IndexOutOfBoundsException if any parameter is invalid or buffer boundaries are exceeded
     * @throws InternalError if VRF signature generation fails
     */
    public static void signVrf(byte[] privateKey, byte[] message, int messageOffset, int messageLength, byte[] random, byte[] output, int offset) {
        var result = gen_x.generalized_xveddsa_25519_sign(
                Objects.requireNonNull(output, "output cannot be null"),
                Objects.checkFromIndexSize(offset, VRF_SIGNATURE_LENGTH, output.length),
                checkKey(privateKey, 0),
                Objects.requireNonNull(message, "message cannot be null"),
                Objects.checkFromIndexSize(messageOffset, messageLength, message.length),
                messageLength,
                checkVrfSignatureRandom(random)
        );
        if(!result) {
            throw new InternalError("generalized_xveddsa_25519_sign failed");
        }
    }

    /**
     * Generates random data for VRF signature operations.
     *
     * <p><strong>Note:</strong> While this method generates random data in the expected format,
     * the current VRF implementation may not utilize this randomness. This method is provided
     * for API completeness and future enhancements.</p>
     *
     * @return 32 bytes of cryptographically secure random data
     * @throws RuntimeException if the secure random generator is not available
     * @see #signVrf(byte[], byte[], byte[])
     */
    public static byte[] randomVrfSignatureData() {
        var random = new byte[VRF_LENGTH];
        RANDOM.nextBytes(random);
        return random;
    }

    /**
     * Verifies a VRF signature and extracts the verifiable random output.
     *
     * <p>This method both verifies the cryptographic proof and extracts the pseudorandom
     * value that was computed. The verification ensures that:</p>
     * <ul>
     *   <li>The signature was created by the holder of the corresponding private key</li>
     *   <li>The random output was correctly computed from the input message</li>
     *   <li>The output is the unique valid result for this key-message pair</li>
     * </ul>
     *
     * <p><strong>Example:</strong></p>
     * <pre>{@code
     * byte[] privateKey = Curve25519.randomPrivateKey();
     * byte[] publicKey = Curve25519.getPublicKey(privateKey);
     * byte[] input = "random seed".getBytes();
     *
     * // Create VRF proof
     * byte[] vrfSignature = Curve25519.signVrf(privateKey, input, null);
     *
     * // Verify and extract random output
     * try {
     *     byte[] randomOutput = Curve25519.verifyVrfSignature(publicKey, input, vrfSignature);
     *     // randomOutput contains 32 bytes of verifiable randomness
     * } catch (SignatureException e) {
     *     // Invalid signature or verification failed
     * }
     * }</pre>
     *
     * @param publicKey The 32-byte public key for verification
     * @param message The original input message
     * @param signature The 96-byte VRF signature to verify
     * @return A 32-byte verifiable random output derived from the input
     * @throws SignatureException if the VRF signature is invalid or verification fails
     * @throws NullPointerException if any parameter is null
     * @throws IndexOutOfBoundsException if any parameter has invalid length
     * @see #signVrf(byte[], byte[], byte[])
     */
    public static byte[] verifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature) throws SignatureException {
        var output = new byte[VRF_LENGTH];
        var result = gen_x.generalized_xveddsa_25519_verify(
                output,
                0,
                signature,
                0,
                checkKey(publicKey, 0),
                0,
                Objects.requireNonNull(message, "message cannot be null"),
                0,
                message.length
        );
        if(result != 0) {
            throw new SignatureException("Signature verification failed");
        }
        return output;
    }

    /**
     * Verifies a VRF signature with precise buffer control and extracts the random output.
     *
     * <p>This method provides maximum flexibility for applications requiring direct buffer
     * manipulation while performing VRF verification and output extraction.</p>
     *
     * @param publicKey Buffer containing the public key
     * @param publicKeyOffset Starting position of the public key
     * @param message Buffer containing the original input message
     * @param messageOffset Starting position of the message
     * @param messageLength Number of bytes in the message
     * @param signature Buffer containing the VRF signature
     * @param signatureOffset Starting position of the signature
     * @param output Buffer to store the 32-byte random output
     * @param offset Starting position in the output buffer
     * @throws SignatureException if the VRF signature verification fails
     * @throws NullPointerException if any buffer is null
     * @throws IndexOutOfBoundsException if any parameter is invalid or buffer boundaries are exceeded
     */
    public static void verifyVrfSignature(byte[] publicKey, int publicKeyOffset, byte[] message, int messageOffset, int messageLength, byte[] signature, int signatureOffset, byte[] output, int offset) throws SignatureException {
        var result = gen_x.generalized_xveddsa_25519_verify(
                Objects.requireNonNull(output, "output cannot be null"),
                Objects.checkFromIndexSize(offset, VRF_LENGTH, output.length),
                Objects.requireNonNull(signature, "signature cannot be null"),
                Objects.checkFromIndexSize(signatureOffset, VRF_SIGNATURE_LENGTH, signature.length),
                checkKey(publicKey, publicKeyOffset),
                Objects.checkFromIndexSize(publicKeyOffset, KEY_LENGTH, publicKey.length),
                Objects.requireNonNull(message, "message cannot be null"),
                Objects.checkFromIndexSize(messageOffset, messageLength, message.length),
                messageLength
        );
        if(result != 0) {
            throw new SignatureException("Signature verification failed");
        }
    }

    /**
     * Validates that a key has the correct length for Curve25519 operations.
     *
     * @param key The key to validate
     * @return The same key if valid
     * @throws NullPointerException if the key is null
     * @throws IndexOutOfBoundsException if the key length is not exactly 32 bytes
     */
    private static byte[] checkKey(byte[] key, int offset) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.checkFromIndexSize(offset, KEY_LENGTH, key.length);

        return key;
    }

    /**
     * Validates random data for signature operations.
     *
     * @param random The random data to validate (may be null)
     * @return The same random data if valid
     * @throws IndexOutOfBoundsException if non-null random data has incorrect length
     */
    private static byte[] checkSignatureRandom(byte[] random) {
        if (random != null && random.length != SIGNATURE_LENGTH) {
            throw new IndexOutOfBoundsException(String.format("Invalid random length: expected %s, got %s", SIGNATURE_LENGTH, random.length));
        }
        return random;
    }

    /**
     * Validates random data for VRF signature operations.
     *
     * @param random The random data to validate (may be null)
     * @return The same random data if valid
     * @throws IndexOutOfBoundsException if non-null random data has incorrect length
     */
    private static byte[] checkVrfSignatureRandom(byte[] random) {
        if (random != null && random.length != VRF_LENGTH) {
            throw new IndexOutOfBoundsException(String.format("Invalid random length: expected %s, got %s", VRF_LENGTH, random.length));
        }
        return random;
    }
}
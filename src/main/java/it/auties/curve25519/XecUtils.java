package it.auties.curve25519;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;

import static org.bouncycastle.asn1.edec.EdECObjectIdentifiers.id_X25519;

/**
 * Utility class for XEC public and private keys
 */
public class XecUtils {
    /**
     * The name of the algorithm used for Curve25519
     */
    private static final String KEY_ALGORITHM = "X25519";

    /**
     * Converts a raw public key to a XEC public key
     *
     * @param rawPublicKey the raw public key to convert
     * @return a non-null XECPublicKey
     */
    public static XECPublicKey toPublicKey(byte[] rawPublicKey){
        try {
            Objects.requireNonNull(rawPublicKey, "Public key cannot be null!");
            var keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            var publicKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(id_X25519), rawPublicKey);
            var publicKeySpec = new X509EncodedKeySpec(publicKeyInfo.getEncoded());
            return (XECPublicKey) keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException | ClassCastException exception) {
            throw new UnsupportedOperationException("Missing Curve25519 implementation", exception);
        } catch (IOException | InvalidKeySpecException exception) {
            throw new RuntimeException("Internal exception during key generation", exception);
        }
    }

    /**
     * Converts a raw private key to a XEC private key
     *
     * @param rawPrivateKey the raw private key to convert
     * @return a non-null XECPrivateKey
     */
    public static XECPrivateKey toPrivateKey(byte[] rawPrivateKey){
        try {
            Objects.requireNonNull(rawPrivateKey, "Private key cannot be null!");
            var keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            var privateKeyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(id_X25519), new DEROctetString(rawPrivateKey));
            var privateKey = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
            return (XECPrivateKey) keyFactory.generatePrivate(privateKey);
        } catch (NoSuchAlgorithmException | ClassCastException exception) {
            throw new UnsupportedOperationException("Missing Curve25519 implementation", exception);
        } catch (IOException | InvalidKeySpecException exception) {
            throw new RuntimeException("Internal exception during key generation", exception);
        }
    }

    /**
     * Converts the input public key in a raw public key
     *
     * @param publicKey the public key to convert
     * @return a non-null array of bytes
     */
    public static byte[] toBytes(XECPublicKey publicKey) {
        try {
            Objects.requireNonNull(publicKey, "Public key cannot be null!");
            var x25519PublicKeyParameters = (X25519PublicKeyParameters) PublicKeyFactory.createKey(publicKey.getEncoded());
            return x25519PublicKeyParameters.getEncoded();
        } catch (IOException exception) {
            throw new RuntimeException("Cannot extract public key", exception);
        }
    }

    /**
     * Converts the input private key in a raw private key
     *
     * @param privateKey the private key to convert
     * @return a non-null array of bytes
     */
    public static byte[] toBytes(XECPrivateKey privateKey) {
        return Optional.of(privateKey)
                .flatMap(XECPrivateKey::getScalar)
                .orElseThrow(() -> new NoSuchElementException("Private key cannot be null!"));
    }
}

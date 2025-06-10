package it.auties.curve25519;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.*;

public class Curve25519Test {
    @Test
    public void generateKeyPair() {
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
    }

    @Test
    public void calculateSharedSecret(){
        var ourPrivateKey = Curve25519.randomPrivateKey();
        var ourPublicKey = Curve25519.getPublicKey(ourPrivateKey);

        var theirPrivateKey = Curve25519.randomPrivateKey();
        var theirPublicKey = Curve25519.getPublicKey(theirPrivateKey);

        var ourSharedSecret = Curve25519.sharedKey(theirPublicKey, ourPrivateKey);
        var theirSharedSecret = Curve25519.sharedKey(ourPublicKey, theirPrivateKey);

        Assertions.assertArrayEquals(ourSharedSecret, theirSharedSecret, "Secret mismatch");
    }

    @Test
    public void calculateAndVerifySignature(){
        var message = randomMessage();
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var signature = Curve25519.sign(privateKey, message);
        var verified = Curve25519.verifySignature(publicKey, message, signature);
        Assertions.assertTrue(verified, "Signature mismatch");
    }

    private static byte[] randomMessage() {
        var random = new SecureRandom();
        var message = new byte[32];
        random.nextBytes(message);
        return message;
    }
}

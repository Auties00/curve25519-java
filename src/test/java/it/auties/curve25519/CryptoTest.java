package it.auties.curve25519;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

public class CryptoTest {
    @Test
    public void generateKeyPair(){
        Curve25519.randomKeyPair();
    }

    @Test
    public void generateKeys(){
        var privateKey = Curve25519.randomPrivateKey();
        Curve25519.forPrivateKey(privateKey);
    }

    @Test
    public void calculateSharedSecret(){
        var keyPair = Curve25519.randomKeyPair();
        Curve25519.sharedKey(keyPair);
    }

    @Test
    public void calculateAndVerifySignature(){
        var random = new SecureRandom();
        var message = new byte[32];
        random.nextBytes(message);
        var keyPair = Curve25519.randomKeyPair();
        var signature = Curve25519.sign(keyPair, message, true);
        Assertions.assertTrue(Curve25519.verifySignature(keyPair.getPublic(), message, signature),
                "Signature mismatch");
    }
}

package com.github.auties00.curve25519;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class Curve25519Test {

    @Test
    public void generateKeyPair() {
        var privateKey = Curve25519.randomPrivateKey();
        assertNotNull(privateKey);
        var publicKey = Curve25519.getPublicKey(privateKey);
        assertNotNull(publicKey);
        assertEquals(32, publicKey.length);
    }

    @Test
    public void calculateSharedSecret() {
        var ourPrivateKey = Curve25519.randomPrivateKey();
        var ourPublicKey = Curve25519.getPublicKey(ourPrivateKey);

        var theirPrivateKey = Curve25519.randomPrivateKey();
        var theirPublicKey = Curve25519.getPublicKey(theirPrivateKey);

        var ourSharedSecret = Curve25519.sharedKey(ourPrivateKey, theirPublicKey);
        var theirSharedSecret = Curve25519.sharedKey(theirPrivateKey, ourPublicKey);

        assertArrayEquals(ourSharedSecret, theirSharedSecret);
    }

    @Test
    public void calculateAndVerifySignature() {
        var message = randomMessage();
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var signature = Curve25519.sign(privateKey, message);
        assertTrue(Curve25519.verifySignature(publicKey, message, signature));
    }

    @Test
    public void publicKeyZeroCopy() {
        var privateKey = Curve25519.randomPrivateKey();
        var expected = Curve25519.getPublicKey(privateKey);

        var output = new byte[64];
        var result = Curve25519.getPublicKey(privateKey, output, 16);

        assertSame(output, result);
        var actual = Arrays.copyOfRange(output, 16, 48);
        assertArrayEquals(expected, actual);
    }

    @Test
    public void sharedKeyZeroCopy() {
        var ourPrivateKey = Curve25519.randomPrivateKey();
        var theirPrivateKey = Curve25519.randomPrivateKey();
        var theirPublicKey = Curve25519.getPublicKey(theirPrivateKey);

        var expected = Curve25519.sharedKey(ourPrivateKey, theirPublicKey);

        var publicKeyBuffer = new byte[100];
        System.arraycopy(theirPublicKey, 0, publicKeyBuffer, 20, 32);

        var outputBuffer = new byte[100];
        Curve25519.sharedKey(ourPrivateKey, publicKeyBuffer, 20, outputBuffer, 30);

        var actual = Arrays.copyOfRange(outputBuffer, 30, 62);
        assertArrayEquals(expected, actual);
    }

    @Test
    public void signatureZeroCopy() {
        var privateKey = Curve25519.randomPrivateKey();
        var message = randomMessage(50);
        var random = Curve25519.randomSignatureData();

        var expected = Curve25519.sign(privateKey, message, random);

        var messageBuffer = new byte[100];
        System.arraycopy(message, 0, messageBuffer, 25, message.length);

        var outputBuffer = new byte[100];
        Curve25519.sign(privateKey, messageBuffer, 25, message.length, random, outputBuffer, 18);

        var actual = Arrays.copyOfRange(outputBuffer, 18, 82);
        assertArrayEquals(expected, actual);
    }

    @Test
    public void signatureVerificationZeroCopy() {
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var message = randomMessage(75);
        var signature = Curve25519.sign(privateKey, message);

        var publicKeyBuffer = new byte[100];
        System.arraycopy(publicKey, 0, publicKeyBuffer, 10, 32);

        var messageBuffer = new byte[150];
        System.arraycopy(message, 0, messageBuffer, 40, message.length);

        var signatureBuffer = new byte[100];
        System.arraycopy(signature, 0, signatureBuffer, 15, 64);

        boolean verified = Curve25519.verifySignature(
                publicKeyBuffer, 10,
                messageBuffer, 40, message.length,
                signatureBuffer, 15
        );

        assertTrue(verified);
    }

    @Test
    public void vrfSignatureBasicAndVerify() {
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var message = randomMessage();

        var vrfSignature = Curve25519.signVrf(privateKey, message, null);
        assertEquals(96, vrfSignature.length);

        var vrfOutput = assertDoesNotThrow(() ->
                Curve25519.verifyVrfSignature(publicKey, message, vrfSignature)
        );
        assertEquals(32, vrfOutput.length);
    }

    @Test
    public void vrfSignatureDeterministicWithProvidedRandom() {
        var privateKey = Curve25519.randomPrivateKey();
        var message = randomMessage();
        var random = Curve25519.randomVrfSignatureData();

        var vrfSignature1 = Curve25519.signVrf(privateKey, message, random);
        var vrfSignature2 = Curve25519.signVrf(privateKey, message, random);

        assertArrayEquals(vrfSignature1, vrfSignature2);
    }

    @Test
    public void vrfSignatureUniqueness() {
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var message1 = "message1".getBytes();
        var message2 = "message2".getBytes();

        var vrfOutput1 = assertDoesNotThrow(() ->
                Curve25519.verifyVrfSignature(publicKey, message1, Curve25519.signVrf(privateKey, message1, null))
        );
        var vrfOutput2 = assertDoesNotThrow(() ->
                Curve25519.verifyVrfSignature(publicKey, message2, Curve25519.signVrf(privateKey, message2, null))
        );

        assertFalse(Arrays.equals(vrfOutput1, vrfOutput2));
    }

    @Test
    public void vrfSignatureZeroCopy() {
        var privateKey = Curve25519.randomPrivateKey();
        var message = randomMessage(60);
        var random = Curve25519.randomVrfSignatureData();

        var expected = Curve25519.signVrf(privateKey, message, random);

        var messageBuffer = new byte[120];
        System.arraycopy(message, 0, messageBuffer, 30, message.length);

        var outputBuffer = new byte[150];
        Curve25519.signVrf(privateKey, messageBuffer, 30, message.length, random, outputBuffer, 25);

        var actual = Arrays.copyOfRange(outputBuffer, 25, 121);
        assertArrayEquals(expected, actual);
    }

    @Test
    public void vrfVerificationZeroCopy() throws SignatureException {
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var message = randomMessage(80);
        var vrfSignature = Curve25519.signVrf(privateKey, message, null);

        var expected = Curve25519.verifyVrfSignature(publicKey, message, vrfSignature);

        var publicKeyBuffer = new byte[100];
        System.arraycopy(publicKey, 0, publicKeyBuffer, 20, 32);

        var messageBuffer = new byte[150];
        System.arraycopy(message, 0, messageBuffer, 35, message.length);

        var signatureBuffer = new byte[150];
        System.arraycopy(vrfSignature, 0, signatureBuffer, 27, 96);

        var outputBuffer = new byte[100];

        Curve25519.verifyVrfSignature(
                publicKeyBuffer, 20,
                messageBuffer, 35, message.length,
                signatureBuffer, 27,
                outputBuffer, 34
        );

        var actual = Arrays.copyOfRange(outputBuffer, 34, 66);
        assertArrayEquals(expected, actual);
    }

    @Test
    public void nullInputs() {
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var message = randomMessage();

        assertThrows(NullPointerException.class, () -> Curve25519.getPublicKey(null));
        assertThrows(NullPointerException.class, () -> Curve25519.sign(null, message));
        assertThrows(NullPointerException.class, () -> Curve25519.sharedKey(null, publicKey));
        assertThrows(NullPointerException.class, () -> Curve25519.signVrf(null, message, null));

        assertThrows(NullPointerException.class, () -> Curve25519.sharedKey(privateKey, null));
        assertThrows(NullPointerException.class, () -> Curve25519.verifySignature(null, message, new byte[64]));
        assertThrows(NullPointerException.class, () -> Curve25519.verifyVrfSignature(null, message, new byte[96]));

        assertThrows(NullPointerException.class, () -> Curve25519.sign(privateKey, null));
        assertThrows(NullPointerException.class, () -> Curve25519.verifySignature(publicKey, null, new byte[64]));
        assertThrows(NullPointerException.class, () -> Curve25519.signVrf(privateKey, null, null));
        assertThrows(NullPointerException.class, () -> Curve25519.verifyVrfSignature(publicKey, null, new byte[96]));

        assertThrows(NullPointerException.class, () -> Curve25519.getPublicKey(privateKey, null, 0));
        assertThrows(NullPointerException.class, () -> Curve25519.sharedKey(privateKey, publicKey, 0, null, 0));
        assertThrows(NullPointerException.class, () -> Curve25519.sign(privateKey, message, 0, message.length, null, null, 0));
        assertThrows(NullPointerException.class, () -> Curve25519.signVrf(privateKey, message, 0, message.length, null, null, 0));
    }

    @Test
    public void invalidKeyLengths() {
        var message = randomMessage();
        var validKey = Curve25519.randomPrivateKey();

        byte[][] invalidKeys = {
                new byte[0],
                new byte[16],
                new byte[31],
        };

        for (byte[] invalidKey : invalidKeys) {
            assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.getPublicKey(invalidKey));
            assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.sign(invalidKey, message));
            assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.sharedKey(invalidKey, validKey));
            assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.sharedKey(validKey, invalidKey));
            assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.signVrf(invalidKey, message, null));
            assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.verifySignature(invalidKey, message, new byte[64]));
            assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.verifyVrfSignature(invalidKey, message, new byte[96]));
        }
    }

    @Test
    public void invalidRandomDataLengths() {
        var privateKey = Curve25519.randomPrivateKey();
        var message = randomMessage();

        byte[][] invalidSignatureRandom = {
                new byte[0],
                new byte[32],
                new byte[63],
                new byte[65],
                new byte[128]
        };

        for (byte[] invalidRandom : invalidSignatureRandom) {
            assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.sign(privateKey, message, invalidRandom));
        }

        byte[][] invalidVrfRandom = {
                new byte[0],
                new byte[16],
                new byte[31],
                new byte[33],
                new byte[64]
        };

        for (byte[] invalidRandom : invalidVrfRandom) {
            assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.signVrf(privateKey, message, invalidRandom));
        }
    }

    @Test
    public void bufferOverflowPrevention() {
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var message = randomMessage();

        assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.getPublicKey(privateKey, new byte[31], 0));
        assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.getPublicKey(privateKey, new byte[32], 1));

        assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.sharedKey(privateKey, publicKey, 0, new byte[31], 0));
        assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.sharedKey(privateKey, publicKey, 0, new byte[32], 1));

        assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.sign(privateKey, message, 0, message.length, null, new byte[63], 0));
        assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.sign(privateKey, message, 0, message.length, null, new byte[64], 1));

        assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.signVrf(privateKey, message, 0, message.length, null, new byte[95], 0));
        assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.signVrf(privateKey, message, 0, message.length, null, new byte[96], 1));
    }

    @Test
    public void invalidOffsets() {
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var message = randomMessage();
        var signature = Curve25519.sign(privateKey, message);
        var vrfSignature = Curve25519.signVrf(privateKey, message, null);

        assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.getPublicKey(privateKey, new byte[64], -1));
        assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.sharedKey(privateKey, publicKey, -1, new byte[64], 0));
        assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.verifySignature(publicKey, -1, message, 0, message.length, signature, 0));

        assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.sign(privateKey, message, message.length, 1, null, new byte[64], 0));
        assertThrows(IndexOutOfBoundsException.class, () -> Curve25519.verifyVrfSignature(publicKey, 0, message, 0, message.length, vrfSignature, 97, new byte[32], 0));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 5, 10, 100, 1000, 10000})
    public void variousMessageSizes(int messageSize) {
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var message = randomMessage(messageSize);

        var signature = Curve25519.sign(privateKey, message);
        assertTrue(Curve25519.verifySignature(publicKey, message, signature), "Signature verification failed for message size " + messageSize);

        var vrfSignature = Curve25519.signVrf(privateKey, message, null);
        var vrfOutput = assertDoesNotThrow(() -> Curve25519.verifyVrfSignature(publicKey, message, vrfSignature));
        assertEquals(32, vrfOutput.length);
    }

    @Test
    public void corruptedSignatures() {
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var message = randomMessage();

        var signature = Curve25519.sign(privateKey, message);
        for (int i = 0; i < signature.length; i++) {
            var corrupted = signature.clone();
            corrupted[i] ^= 0xFF;
            assertFalse(Curve25519.verifySignature(publicKey, message, corrupted), "Corrupted signature should not verify (byte " + i + ")");
        }

        var vrfSignature = Curve25519.signVrf(privateKey, message, null);
        for (int i = 0; i < vrfSignature.length; i += 10) {
            var corrupted = vrfSignature.clone();
            corrupted[i] ^= 0x01;
            assertThrows(SignatureException.class, () -> Curve25519.verifyVrfSignature(publicKey, message, corrupted), "Corrupted VRF signature should not verify (byte " + i + ")");
        }
    }

    @Test
    public void wrongPublicKey() {
        var privateKey1 = Curve25519.randomPrivateKey();
        var publicKey1 = Curve25519.getPublicKey(privateKey1);
        var privateKey2 = Curve25519.randomPrivateKey();
        var publicKey2 = Curve25519.getPublicKey(privateKey2);
        var message = randomMessage();

        var signature = Curve25519.sign(privateKey1, message);
        assertFalse(Curve25519.verifySignature(publicKey2, message, signature));

        var vrfSignature = Curve25519.signVrf(privateKey1, message, null);
        assertThrows(SignatureException.class, () -> Curve25519.verifyVrfSignature(publicKey2, message, vrfSignature));
    }

    @Test
    public void modifiedMessage() {
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var message = "original message".getBytes();
        var modifiedMessage = "modified message".getBytes();

        var signature = Curve25519.sign(privateKey, message);
        assertFalse(Curve25519.verifySignature(publicKey, modifiedMessage, signature));

        var vrfSignature = Curve25519.signVrf(privateKey, message, null);
        assertThrows(SignatureException.class, () -> Curve25519.verifyVrfSignature(publicKey, modifiedMessage, vrfSignature));
    }

    private static byte[] randomMessage() {
        return randomMessage(32);
    }

    private static byte[] randomMessage(int size) {
        var random = new SecureRandom();
        var message = new byte[Math.max(0, size)];
        random.nextBytes(message);
        return message;
    }
}


package com.github.auties00.curve25519;

import org.openjdk.jmh.annotations.*;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.NamedParameterSpec;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 3)
@Measurement(iterations = 5)
public class Curve25519Benchmark {

    private KeyPairGenerator keyPairGenerator;
    private KeyAgreement ourKeyAgreement;
    private KeyAgreement theirKeyAgreement;

    @Setup(Level.Trial)
    public void setup() throws GeneralSecurityException {
        keyPairGenerator = KeyPairGenerator.getInstance("XDH");
        keyPairGenerator.initialize(NamedParameterSpec.X25519);
        ourKeyAgreement = KeyAgreement.getInstance("XDH");
        theirKeyAgreement = KeyAgreement.getInstance("XDH");
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public void generateKeyPair() {
        var privateKey = Curve25519.randomPrivateKey();
        Curve25519.getPublicKey(privateKey);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public void calculateSharedSecret(){
        var ourPrivateKey = Curve25519.randomPrivateKey();
        var ourPublicKey = Curve25519.getPublicKey(ourPrivateKey);

        var theirPrivateKey = Curve25519.randomPrivateKey();
        var theirPublicKey = Curve25519.getPublicKey(theirPrivateKey);

        Curve25519.sharedKey(ourPrivateKey, theirPublicKey);
        Curve25519.sharedKey(theirPrivateKey, ourPublicKey);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public void calculateAndVerifySignature(){
        var message = randomMessage();
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var signature = Curve25519.sign(privateKey, message);
        Curve25519.verifySignature(publicKey, message, signature);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public void calculateAndVerifyVrfSignature() throws SignatureException {
        var message = randomMessage();
        var privateKey = Curve25519.randomPrivateKey();
        var publicKey = Curve25519.getPublicKey(privateKey);
        var vrfSignature = Curve25519.signVrf(privateKey, message, null);
        Curve25519.verifyVrfSignature(publicKey, message, vrfSignature);
    }

    private static byte[] randomMessage() {
        var random = new SecureRandom();
        var message = new byte[32];
        random.nextBytes(message);
        return message;
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public void jcaGenerateKeyPair() {
        keyPairGenerator.generateKeyPair();
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public void jcaCalculateSharedSecret() throws GeneralSecurityException {
        var ourKeyPair = keyPairGenerator.generateKeyPair();
        var theirKeyPair = keyPairGenerator.generateKeyPair();

        ourKeyAgreement.init(ourKeyPair.getPrivate());
        ourKeyAgreement.doPhase(theirKeyPair.getPublic(), true);
        ourKeyAgreement.generateSecret();

        theirKeyAgreement.init(theirKeyPair.getPrivate());
        theirKeyAgreement.doPhase(ourKeyPair.getPublic(), true);
        theirKeyAgreement.generateSecret();
    }

    // No signature support in JDK
}
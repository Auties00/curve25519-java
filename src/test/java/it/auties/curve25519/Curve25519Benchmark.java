package it.auties.curve25519;

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

        Curve25519.sharedKey(theirPublicKey, ourPrivateKey);
        Curve25519.sharedKey(ourPublicKey, theirPrivateKey);
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

    private static byte[] randomMessage() {
        var random = new SecureRandom();
        var message = new byte[32];
        random.nextBytes(message);
        return message;
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public void jcaGenerateKeyPair() throws GeneralSecurityException {
        var keyPairGenerator = KeyPairGenerator.getInstance("XDH");
        keyPairGenerator.initialize(NamedParameterSpec.X25519);
        keyPairGenerator.generateKeyPair();
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public void jcaCalculateSharedSecret() throws GeneralSecurityException {
        var ourKeyPairGenerator = KeyPairGenerator.getInstance("XDH");
        ourKeyPairGenerator.initialize(NamedParameterSpec.X25519);
        var ourKeyPair = ourKeyPairGenerator.generateKeyPair();

        var theirKeyPairGenerator = KeyPairGenerator.getInstance("XDH");
        theirKeyPairGenerator.initialize(NamedParameterSpec.X25519);
        var theirKeyPair = theirKeyPairGenerator.generateKeyPair();

        var ourKeyAgreement = KeyAgreement.getInstance("XDH");
        ourKeyAgreement.init(ourKeyPair.getPrivate());
        ourKeyAgreement.doPhase(theirKeyPair.getPublic(), true);
        ourKeyAgreement.generateSecret();

        var theirKeyAgreement = KeyAgreement.getInstance("XDH");
        theirKeyAgreement.init(theirKeyPair.getPrivate());
        theirKeyAgreement.doPhase(ourKeyPair.getPublic(), true);
        theirKeyAgreement.generateSecret();
    }
}

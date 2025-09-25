
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


}
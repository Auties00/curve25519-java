# Curve25519

An implementation of Curve25519 based on Signal's curve25519-java with optimizations and support for zero-copy implementations.
Java 11 is required, could be upgraded if I ever try to use the new vector API to refactor the code inherited from the original implementation.
No dependencies are used, so the project should work on any platform.

### Why not use the built-in implementation?

When this library was first developed at Signal there was no built-in Curve25519 implementation in Java.
While this is no longer the case since Java 11, computing an x25519 signature involves converting keys from x25519 to ed25519, which is not possible using the built-in implementation.
This is the reason why I forked the original repo and decided to update it.

### How to install

#### Maven
Add this dependency to your dependencies in the pom:
```xml
<dependencies>
    <dependency>
        <groupId>com.github.auties00</groupId>
        <artifactId>curve25519</artifactId>
        <version>3.0.1</version>
    </dependency>
</dependencies>
```

#### Gradle
Add this dependency to your build.gradle:
```groovy
implementation 'com.github.auties00:curve25519:3.0.1'
```

### How to use

> **IMPORTANT**: All methods listed offer zero-copy overloads expect for private keys for security reasons.

### Generating a Curve25519 keypair:

```
var privateKey = Curve25519.randomPrivateKey();
var publicKey = Curve25519.getPublicKey(privateKey);
```

### Calculating a shared secret:

```
var sharedSecret = Curve25519.sharedKey(privateKey, publicKey);
```

### Calculating a signature:

```
var signature = Curve25519.sign(privateKey, message);
```

### Verifying a signature:

```
var isValid = Curve25519.verifySignature(publicKey, message, signature);
```

### Calculating a vrf signature:

```
var signature = Curve25519.signVrf(privateKey, message);
```

### Verifying a signature:

```
var vrf = Curve25519.verifyVrfSignature(publicKey, message, signature);
```


### Benchmarks

Java offers a built-in Curve25519 implementation.
Here is a performance comparison between this library and the built-in implementation:
```
Benchmark                                           Mode  Cnt    Score     Error  Units
Curve25519Benchmark.generateKeyPair                 avgt    5   39.442 ±   6.038  us/op
Curve25519Benchmark.calculateSharedSecret           avgt    5  271.292 ±  68.469  us/op
Curve25519Benchmark.calculateAndVerifySignature     avgt    5  247.988 ±  26.949  us/op
Curve25519Benchmark.calculateAndVerifyVrfSignature  avgt    5  784.672 ± 120.641  us/op
Curve25519Benchmark.jcaGenerateKeyPair              avgt    5  119.172 ±  32.055  us/op
Curve25519Benchmark.jcaCalculateSharedSecret        avgt    5  457.237 ±  86.077  us/op
```

## License

Copyright 2015 Open Whisper Systems

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html

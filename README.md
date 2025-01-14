# Curve25519

An implementation of Curve25519 based on Signal's using modern Java features and components of the Java Cryptographic architecture.
Wrappers are reduced to zero and the library is fully modular. Java 11 or higher is required. It should work on any platform.

### How to install

#### Maven
Add this dependency to your dependencies in the pom:
```xml
<dependencies>
    <dependency>
        <groupId>com.github.auties00</groupId>
        <artifactId>curve25519</artifactId>
        <version>1.2</version>
    </dependency>
</dependencies>
```

#### Gradle
Add this dependency to your build.gradle:
```groovy
implementation 'com.github.auties00:curve25519:1.2'
```

### How to use

### Generating a Curve25519 keypair:

```
var keyPair = Curve25519.generateKeyPair();
```

### Calculating a shared secret:

```
var sharedSecret = Curve25519.calculateAgreement(publicKey, privateKey);
```

### Calculating a signature:

```
var signature = Curve25519.calculateSignature(privateKey, message);
```

### Verifying a signature:

```
var isValid = Curve25519.verifySignature(publicKey, message, signature);
```

## License

Copyright 2015 Open Whisper Systems

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html

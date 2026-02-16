# crypto-utils: simple encryption in Java
[![Package Status](https://img.shields.io/badge/status-experimental-yellow)](https://github.com/psteitz/crypto-utils)
[![License](https://img.shields.io/badge/license-apache2-green)](https://github.com/psteitz/crypto-utils/blob/main/LICENSE)

## What is this?

**crypto-utils** is a set of Java utility classes containing static methods to perform AES and PGP encryption/decryption using the JDK or BouncyCastle providers.

## Main Features
Here are the things you can do with crypto-utils:

  - Generate AES or PGP keys.
  - Perform AES or PGP encryption / decription of strings, byte arrays, streams or files.
  - Benchmark performance of crypto operations using JMH.

## Where to get it
The source code is currently hosted on GitHub at:
https://github.com/psteitz/crypto-utils

There is no packaged distribution at this time. To build from source, execute
```mvn clean package``` from the top-level ```crypto-utils``` directory.

## Dependencies
- [BouncyCastle 1.79 - used by BC classes](https://www.bouncycastle.org/)
- Java 11+

## License
[Apache 2.0](LICENSE)

## Documentation

### Key Generation
The ```KeyUtils``` class includes utilities for generating symmetric (AES) and asymmetric (PGP) keys.

#### AES keys
The simplest way to generate an AES key is to use ```KeyUtils.generateAESKey()```
The generated key will have the default length of 256 bits.  The length (in bits) can also be supplied as a parameter to ```generateAESKey```.

The ```KeyUtils``` class also supports password based key derivation.  Use ```generateAESKeyFromPhrase``` to generate keys derived from passphrase / salt combinations.  The number of hashing iterations can be specified, but defaults to a reasonable number.  Salt bytes should be at least 16 in length and these bytes should be random.  Recovering the key requires both the salt and the passphrase.

#### PGP keys
To generate a random key pair, use ```KeyUtils.generateKeyPair()```.  The public and private keys in the pair can be accessed using the getters provided by the [JCA KeyPair](https://docs.oracle.com/en/java/javase/12/docs/api/java.base/java/security/KeyPair.html) returned by this method.  The argumentless version of this method uses the default algorithm (RSA) and key length (3072 bits).  These can be overridden by using the versions that supply these parameters.

```KeyUtils``` also supports reading PGP keys from OpenPGP-compliant exported keyrings.  The methods ```readSecretKeys``` and ```readPublicKeys``` read lists of [PGPSecretKey](https://javadoc.io/static/org.bouncycastle/bcpg-jdk15on/1.66/org/bouncycastle/openpgp/PGPSecretKey.html) and [PGPPublicKey](https://javadoc.io/static/org.bouncycastle/bcpg-jdk15on/1.64/org/bouncycastle/openpgp/PGPPublicKey.html) from ASCII-armored input streams.

### AES Encryption
The ```AES``` class provides AES encryption utilities.  Supported cipher methods all perform chained block encryption, so an [initialization vector](https://en.wikipedia.org/wiki/Initialization_vector) (iv) must be provided when performing encryption.  You can create your own iv and pass it to the ```encrypt``` and ```decrypt``` methods, or use the versions of these methods that do not take an iv as argument.  In the latter case, an iv will be randomly generated, added to the front of the encrypted data by ```encrypt``` and parsed out by ```decrypt```.  The AES transformation used is [GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode).  It is important not to reuse iv vectors if you supply them.

Both platform-default (Sun) and BouncyCastle providers are supported. The default is platform default. To use the BouncyCastle provider, use ```AES.setProvider(AES.BC_PROVIDER)```;

The encryption methods that work with fixed-length byte arrays or strings Base64 encode the ciphertext that they create.  The corresponding decryption methods decode input before encryption.  The stream and file-based methods do not use Base64 encoding.

### PGP Encryption
To use the BouncyCastle OpenPGP implementation, use the ```BCPGP``` class.  The encryption / decryption methods implemented by this class all implement [session-based PGP](https://datatracker.ietf.org/doc/html/rfc4880#page-17).
PGP is used only in the transmission of a securely generated symmetric session key, which is the key used to encrypt the input message.  The session key is generated prior to encryption, PGP encrypted for the recipients public key and included in the encrypted message. ```BCPGP``` uses AES for symmetric encryption.

The ```JdkPGP``` class implements RSA encryption using the JDK with transformation ```RSA/ECB/OAEPWithSHA-256AndMGF1Padding```.  The implementation in this class does not use the session-based PGP protocol — cleartext inputs are directly encrypted using RSA in blocks.  This is suitable only for small payloads; for bulk data, prefer ```BCPGP``` which uses a hybrid session-key approach.

### Benchmarks
Code to run JMH benchmarks is in ```/benchmarks```.  To run the benchmarks, you need to first install the main code using ```mvn install``` from the top-level ```crypto-utils``` directory.  To compile the benchmarks, execute ```mvn package``` from the ```benchmarks``` directory and then

 ```java -jar target/benchmarks.jar.```

## Development
Issues can be reported [here](https://github.com/psteitz/crypto-utils/issues).  PRs are welcome [here](https://github.com/psteitz/crypto-utils/pulls).


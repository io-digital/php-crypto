# Clockwork
Easy to use PHP cryptography library based on [openssl](http://php.net/manual/en/book.openssl.php) and [GMP](http://php.net/manual/en/book.gmp.php)

## About
The aim of this library is to provide a general purpose cryptography library for PHP with as few dependencies as possible
while being cryptographically secure and very easy to use. Additionally **Clockwork** is also a project that hopes to provide
insight into the vast field of cryptography and assist developers in picking the correct scheme for their desired application.
An experienced developer familiar with cryptography jargon will have no problem implementing an encryption scheme using
[openssl](http://php.net/manual/en/book.openssl.php), but, those less familiar with cryptography may need to implement an
appropriate scheme they can trust to be secure without understanding the mathematical principles behind it.

## Requirements
- PHP 7
- [openssl](http://php.net/manual/en/book.openssl.php) extension
- [GMP](http://php.net/manual/en/book.gmp.php) extension

## Current Features
- Supports all the ciphers available in the [openssl module](http://php.net/manual/en/function.openssl-get-cipher-methods.php)
- Diffie-Hellman implementation for asymmetric encryption using [GMP](ttp://php.net/manual/en/book.gmp.php)
- Custom signiture generation and verification
- hmac generation

## Roadmap
- Support for DSA, RSA and others
- More information about cryptography

## Usage example
Here is an example using a 32byte random number as the private key for each party, Diffie-Hellman
and AES-256-CBC encryption.

1. Each party generates a random number/key
2. Each party derives a public key
3. The public keys are exchanged openly
4. Each party derives **the same** shared secret using their own private key and the
other party's public key.
5. The parties can now communicate securely

```php
<?php

$c = new IoDigital\Clockwork();
// 1.
$alice_private_key = $c->makeKey(32);
$bob_private_key = $c->makeKey(32);
// 2.
$alice_public_key = $c->derivePublic($alice_private_key);
$bob_public_key = $c->derivePublic($bob_private_key);

// 3.
// Public keys are exchanged openly over the network somehow....

// 4.
$alice_secret = $c->deriveSharedSecret($alice_private_key, $bob_public_key);
$bob_secret = $c->deriveSharedSecret($bob_private_key, $alice_public_key);


// 5.

// Alice encrypts a message
$iv = $c->makeIv(); // New random Input Vector
$encrypted = $c->encrypt("Secret message from Alice to Bob", $alice_secret, $iv);

// The encrypted data is sent to bob
$decrypted = $c->decrypt($encrypted, $bob_secret, $iv);
echo "\nDecrypted: $decrypted\n";

```

## Technical stuff
### Signatures
hmac/hash/DSA/RSA
### Curves
Which curves to use?
### Random numbers
Getting secure random numbers
### Prime numbers
By default we're using a 1563bit prime number to do the DH modular arithmetic. For your convenience a 2048bit and 3072bit prime are also included. However, it's important to remember that given *g^x mod p* where *g* is the generator, *p* is prime and *x* is the secret, the smaller *x* is, the faster this runs.  However, the bit-width of x should be at least twice the symmetric-key equivalent strength of the discrete logarithm for a given size of p.  What that is exactly is a subject of debate, but the idea is that g^x needs to be bazillions of times larger than p because working out how many times it wrapped
past p is a successful attack.
## Contributing
Please do
## License
Apache License 2.0

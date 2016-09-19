# php-crypto
Easy to use PHP cryptography library with Diffie-Hellman public key and secret generation.

## About
The aim of this library is to provide a general purpose cryptography library for PHP with as few dependencies as possible
while being cryptographically secure. PHP's standard library together with the `mcrypt` and `openssl` modules provide everything needed for this but requires some manual implementation.

## Requirements
- PHP 7
- [mcrypt](http://php.net/manual/en/book.mcrypt.php) extension
- [openssl](http://php.net/manual/en/book.openssl.php) extension
- [GMP](http://php.net/manual/en/book.gmp.php) extension

## Features
- Supports all the ciphers available to the PHP [openssl module](http://php.net/manual/en/function.openssl-get-cipher-methods.php)
- Diffie-Hellman implementation for asymmetric encryption using [GMP](ttp://php.net/manual/en/book.gmp.php)
- Signiture generation and verification
- hmac generation

## Limitations
- Setting the random source to `MCRYPT_RAND` should allow the lib to work on Windows but it is not safe for production
- The lib is unopinionated and will not enforce best practices and standards for cryptography

## Usage example

```php
<?php
require 'Crypto.php';

$c = new Crypto();
// Alice makes her keys
$alice_private_key = $c->makeKey(32);
$alice_public_key = $c->derivePublic($alice_private_key);

// Bob makes his keys
$bob_private_key = $c->makeKey(32);
$bob_public_key = $c->derivePublic($bob_private_key);

// Public keys are exchanged through the network somehow....

// They each derive the same shared secret
$alice_secret = $c->deriveSharedSecret($alice_private_key, $bob_public_key);
$bob_secret = $c->deriveSharedSecret($bob_private_key, $alice_public_key);


// Secure communication can now take place

// Alice encrypts a message
$iv = $c->makeIv(); // New random Input Vector
$encrypted = $c->encrypt("Secret message from Alice to Bob", $alice_secret, $iv);

// The encrypted data is sent to bob
$decrypted = $c->decrypt($encrypted, $bob_secret, $iv);
echo "\nDecrypted: $decrypted\n";

```

## Technical stuff
By default we're using a 1563bit prime number to do the DH modular arithmetic. For your convenience a 2048bit and 3072bit prime are also included. However, it's important to remember that given *g^x mod p* where *g* is the generator, *p* is prime and *x* is the secret, the smaller *x* is, the faster this runs.  However, the bit-width of x should be at least twice the symmetric-key equivalent strength of the discrete logarithm for a given size of p.  What that is exactly is a subject of debate, but the idea is that g^x needs to be bazillions of times larger than p because working out how many times it wrapped
past p is a successful attack.

## License
GNU GPL v3

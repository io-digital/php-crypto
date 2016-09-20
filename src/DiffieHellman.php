<?php
/**
 * Crypto is a library for eleptic curve cryptography in PHP7
 * @package
 * @author      Werner Roets <werner@io.co.za>
 * @license     TBD
 * @version     0.1
 * @link        http://githubrepowillgohere
 * Alice and Bob agree to use a modulus p = 23 and base g = 5 (which is a primitive root modulo 23).
 * Alice chooses a secret integer a = 6, then sends Bob A = ga mod p
 *     A = 56 mod 23 = 8
 *  Bob chooses a secret integer b = 15, then sends Alice B = gb mod p
 *     B = 515 mod 23 = 19
 * Alice computes s = Ba mod p
 *     s = 196 mod 23 = 2
 * Bob computes s = Ab mod p
 *     s = 815 mod 23 = 2
 * Alice and Bob now share a secret (the number 2).
 */

 /**
  * DiffieHellman.php
  * @author     Werner Roets <werner@io.co.za>
  * @copyright  2016
  * @license    TBD
  * @link       http://githubrepowillgohere
  */
class DiffieHellman {
    /**
     * Diffie-Hellman Magic. Derive a public key from a private key
     * @param GMP $private_key
     * @param GMP $prime
     * @param GMP $generator
     * @return GMP $derived_public_key
     */
    public static function derive_public_gmp( GMP $private_key, GMP $prime, GMP $generator) : GMP {
        return gmp_powm($generator, $private_key, $prime);
    }

    /**
     * Diffie-Hellman Magic. Derive a shared secret from two a public and private key
     * @param GMP $my_private_key
     * @param GMP $their_public_key
     * @param GMP $prime
     * @return GMP $derived_shared_secret
     */
    public static function derive_shared_gmp( GMP $my_private_key, GMP $their_public_key, GMP $prime) : GMP {
        return gmp_powm($their_public_key, $my_private_key, $prime);
    }

    /**
     * Only for reference. This will not work with even remotely large numbers (like 30, yes I'm serious)
     */
    public static function derive_public_lp( string $private_key, string $prime, string $generator) : string {
        return (string)($generator**$private_key) % $prime;
    }

    /**
     * Only for reference. This will not work with even remotely large numbers (like 30, yes I'm serious)
     */
    public static function derive_shared_lp( string $my_private_key, string $their_public_key, string $prime) : string {
        return (string)($their_public_key**$my_private_key % $prime);
    }
}

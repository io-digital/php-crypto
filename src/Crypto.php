<?php
/**
 * Crypto is a library for eleptic curve cryptography in PHP7
 * @package
 * @author      Werner Roets <werner@io.co.za>
 * @license     TBD
 * @version     0.1
 * @link        http://githubrepowillgohere
 */
require 'Prime.php';
require 'DiffieHellman.php';
/**
 * Crypto.php
 * @author     Werner Roets <werner@io.co.za>
 * @copyright  2016
 * @license    TBD
 * @link       http://githubrepowillgohere
 */
class Crypto {

    // These values serve as defaults
    /**
     * The encryption cipher algorithm used. This value must correspond
     * to OpenSSL's string name for the cipher algorithm
     * @var string
     */
    private $cipher_algorithm = 'aes-256-cbc';

    /**
     * The hash algorithm used. The value must correspond to
     * a string name accepted by PHP's hash(). Available
     * @var string
     */
    private $hash_algorithm = 'sha256';
    /**
     * Cipher padding mode. This must be one of the constants
     * provided by OpenSSL.
     * @var string
     */
    private $cipher_padding = OPENSSL_RAW_DATA;

    /**
     * Random source. This must be one of the constants
     * provided by MCrypt. MCRYPT_DEV_URANDOM is recommended.
     * @var int
     */
    private $random_source = MCRYPT_DEV_URANDOM;

    /**
     * Select one of the predefined primes in Prime.php
     * @var int
     */
    private $prime_size = Prime::BIT_1563;

    /**
     * The constructor takes an array as it's only argument.
     * This array should contain keys corresponding to the
     * available options.
     * e.g
     *  $options = [
     *      'cipher_algorithm' => 'aes-256-cbc',
     *      'cipher_padding' => OPENSSL_RAW_DATA,
     *      'random_source' => MCRYPT_DEV_URANDOM,
     *  ]
     * @var array
     */
    public function __construct( $options = null ) {
        if( $options !== null ) {
            if( is_array($options) ) {
                // Cipher Algorithm
                if( in_array('cipher_algorithm', $options) ){
                    $available_algorithms = openssl_get_cipher_methods(true);
                    if( in_array($options['cipher_algorithm'], $available_algorithms) ) {
                        $this->cipher_algorithm = $options['cipher_algorithm'];
                    }else {
                        throw new Exception("Unsupported cipher algorithm");
                    }
                }
                // Cipher Padding
                if( in_array('cipher_padding', $options) ) {
                    $available_paddings = $this->getAvailableCipherPaddings();
                    // TODO
                }

                if( in_array('random_source',$options) ) {
                    $available_random_sources = $this->getAvailableRandomSources();
                    // TODO
                }
            }else{
                throw new Exception("Options passed must be an array");
            }
        }
        // Use defaults
    }

    /**
     * Get a list of available cipher algorithm provided by
     * the OpenSSL module. To set Crypto to use one of these ciphers
     * pass the corresponding string to the constructor in the options
     * array.
     * @return array
     */
    public function getAvailableCipherMethods() : array {
        return openssl_get_cipher_methods(true);
    }

    /**
     * Get a list of available cipher paddings provided by
     * the OpenSSL module. To set Crypto to use one of these paddings
     * pass the corresponding value to the constructor in the options
     * array.
     * @return array
     */
    public function getAvailableCipherPaddings() : array {
        return [
            'OPENSSL_RAW_DATA',
            'OPENSSL_ZERO_PADDING'
        ];
    }

    /**
     * Get a list of available random sources.
     * MCRYPT_RAND - System (libc)
     * MCRYPT_DEV_URANDOM - /dev/urandom (recommended)
     * MCRYPT_DEV_RANDOM - /dev/random
     * @return array
     */
    public function getAvailableRandomSources() : array {
        return [
                'MCRYPT_DEV_URANDOM',
                'MCRYPT_DEV_RANDOM',
                'MCRYPT_RAND'
        ];
    }

    public function getAvailableHashAlgorithms() : array {
        return hash_algos();
    }

    /**
     * Encrypt a string with a key and input vector
     * @param string $data - The data to encrypt
     * @param string $secret - The secret key used to encrypt and decrypt
     * @param string $iv - The input vector used
     * @return string - The encrypted data as a binary string
     */
    public function encrypt( string $data, string $secret, string $iv) : string {
        return openssl_encrypt(
            $data,
            $this->cipher_algorithm,
            $secret,
            OPENSSL_RAW_DATA,
            $iv
        );
    }
    /**
     * Encrypt a string with a key and input vector
     * @param string $data - The data to decrypt as a binary string
     * @param string $secret - The secret key used to encrypt and decrypt
     * @param string $iv - The input vector used
     * @return string - The decrypted data as a string
     */
    public function decrypt( string $data, string $secret, string $iv) : string {
        return openssl_decrypt(
            $data ,
            $this->cipher_algorithm,
            $secret,
            OPENSSL_RAW_DATA,
            $iv
        );
    }

    /**
     * Derive a public key from a private key using DiffieHellman math
     * @param string $private_key - The key to derive from as a Hexadecimal string
     * @return string - The derived public key as a Hexadecimal string
     */
    public function derivePublic( string $private_key ) : string {
        if( !ctype_xdigit($private_key) ) {
            throw new Exception("Key must be a Hexadecimal string");
        }
        $prime_gmp = Prime::asGMP(Prime::BIT_1563);
        $generator_gmp = gmp_init(2);
        $key = gmp_init('0x'.$private_key);
        $public_gmp = DiffieHellman::derive_public_gmp($key, $prime_gmp, $generator_gmp);
        return gmp_strval($public_gmp,16);
    }

    /**
     * Derive a shared secret from two keys
     * @param string $our_private_key - The key to derive from as a Hexadecimal string
     * @param string $their_public_key - The key to derive from as a Hexadecimal string
     * @return string - The derived shared secret as a Hexadecimal string
     */
    public function deriveSharedSecret( string $our_private_key, string $their_public_key) : string {
        if( !ctype_xdigit($our_private_key) || !ctype_xdigit($their_public_key)) {
            throw new Exception("Keys must be Hexadecimal strings");
        }
        $prime_gmp = Prime::asGMP(Prime::BIT_1563);
        $our_private_key_gmp = gmp_init('0x'.$our_private_key);
        $their_public_key_gmp = gmp_init('0x'.$their_public_key);
        $secret_gmp = DiffieHellman::derive_shared_gmp($our_private_key_gmp, $their_public_key_gmp, $prime_gmp);
        return gmp_strval($secret_gmp, 16);
    }

    /**
     * Make a new random number with a cryptographically safe random number generator
     * @param int $length of Hexadecimal number. N.B Odd numbers will be rounded down
     * @return string - A Hexadecimal representation of the random number
     */
    public function makeKey( int $length = 32) : string {
        return bin2hex(mcrypt_create_iv( $length / 2, MCRYPT_DEV_URANDOM ));
    }

    /**
     * Make an input vector of the length expected by the currently set algorithm
     * @return string - A Hexadecimal representation of the random number
     */
    public function makeIv() : string {
        $length = openssl_cipher_iv_length($this->cipher_algorithm);
        return bin2hex(mcrypt_create_iv( $length / 2, MCRYPT_DEV_URANDOM ));
    }

    /**
     * Make an Hmac hash of the data and key
     * @return string - A Hexadecimal representation of the hmac
     */
    public function createHmac(string $data, string $key) : string {
        // NB Hashing algorithm is probably different to encryption algorithm
        return hash_hmac($this->hash_algorithm, $data, $key);
    }
    /**
     * Generate a cryptographic signature of some data with a provided key
     * @param string $data - The data to generate a signature from
     * @param string $key - The key used to sign with
     * @param string $iv - The iv used when encrypting the hash
     * @param bool $binary - Will output binary if true. Default is hexits
     * @return string $signature - The signature generated as binary or hexits
     */
    public function sign( string $data, string $key, string $iv, bool $binary = false ) : string {
        $digest = hash($this->hash_algorithm, $data, $binary);
        $signature = $this->encrypt($digest, $key, $iv);
        return ['signature' => $signature, 'iv' => $iv];
    }

    public function verify( string $signature, string $data, string $key, string $iv, bool $binary = false) : bool {
        $decrypted_digest = $this->decrypt($signature, $key, $iv);
        $new_digest = hash($this->hash_algorithm, $data, $binary);
        if( $decrypted_digest === $new_digest ) {
            return true;
        }
        return false;
    }
}

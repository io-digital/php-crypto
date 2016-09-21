<?php
/**
 * Clockwork
 * @package
 * @author      Werner Roets <werner@io.co.za>
 * @license     GNU GPL v3
 * @version     1.0
 * @link        https://github.com/io-digital/clockwork
 */

namespace IoDigital;

class Clockwork {

    /**
     * Safe large prime numbers
     * http://tools.ietf.org/html/rfc3526
     */
    const PRIME_1563BIT = '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF';
    const PRIME_2048BIT = '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF';
    const PRIME_3072BIT = '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';

    // These values serve as defaults
    /**
     * The encryption cipher algorithm used. This value must correspond
     * to OpenSSL's string name for the cipher algorithm
     * @var string
     */
    private $cipher_algorithm;

    /**
     * Cipher padding mode. This must be one of the constants
     * provided by OpenSSL.
     * @var string
     */
    private $cipher_padding;

    /**
     * The hash algorithm used. The value must correspond to
     * a string name accepted by PHP's hash(). Available
     * @var string
     */
    private $hash_algorithm;

    /**
     * P
     */
    private $prime;

    /**
     * TODO
     */
    private $prime_name;
    /**
     * G
     */
     private $generator;

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
        // Set defaults
        $this->generator = 2;
        $this->prime_name = 'Clockwork\PRIME_1563BIT';
        $this->prime = constant($this->prime_name);
        $this->hash_algorithm = 'sha256';
        $this->cipher_padding = OPENSSL_RAW_DATA;
        $this->cipher_algorithm = 'aes-256-cbc';

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
                    if( in_array(strtoupper($options['cipher_padding'], $available_paddings)) ) {
                        $this->cipher_padding = strtoupper($options['cipher_algorithm']);
                    } else {
                        throw new \Exception("Unsupported cipher padding");
                    }
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

    /**
     * TODO
     */
    public function getAvailableHashAlgorithms() : array {
        return hash_algos();
    }

    /**
     * TODO
     */
    public function getAvailablePrimes() : array {
        return [
            'Clockwork\PRIME_1563BIT',
            'Clockwork\PRIME_2048BIT',
            'Clockwork\PRIME_3072BIT'
        ];
    }

    /**
     * Diffie-Hellman Magic. Derive a public key from a private key
     * @param GMP $private_key
     * @param GMP $prime
     * @param GMP $generator
     * @return GMP $derived_public_key
     */
    private static function derive_public_gmp( GMP $private_key, GMP $prime, GMP $generator) : GMP {
        return gmp_powm($generator, $private_key, $prime);
    }

    /**
     * Diffie-Hellman Magic. Derive a shared secret from two a public and private key
     * @param GMP $my_private_key
     * @param GMP $their_public_key
     * @param GMP $prime
     * @return GMP $derived_shared_secret
     */
    private static function derive_shared_gmp( GMP $my_private_key, GMP $their_public_key, GMP $prime) : GMP {
        return gmp_powm($their_public_key, $my_private_key, $prime);
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
    public function derivePublicKey( string $private_key ) : string {

        if( !ctype_xdigit($private_key) ) {
            throw new Exception("Key must be a Hexadecimal string");
        }

        $prime_gmp = gmp_init(constant($this->prime));
        $generator_gmp = gmp_init($this->generator);
        $key_gmp = gmp_init('0x'.$private_key);

        $public_gmp = self::derive_public_gmp($key_gmp, $prime_gmp, $generator_gmp);
        return gmp_strval($public_gmp,16);
    }

    /**
     * Derive a shared secret from two keys
     * @param string $our_private_key - The key to derive from as a Hexadecimal string
     * @param string $their_public_key - The key to derive from as a Hexadecimal string
     * @return string - The derived shared secret as a Hexadecimal string
     */
    public function deriveSharedSecretKey( string $our_private_key, string $their_public_key) : string {

        if( !ctype_xdigit($our_private_key) || !ctype_xdigit($their_public_key) ) {
            throw new Exception("Keys must be Hexadecimal strings");
        }
        $prime_gmp = gmp_init(constant($this->prime));
        $our_private_key_gmp = gmp_init('0x'.$our_private_key);
        $their_public_key_gmp = gmp_init('0x'.$their_public_key);

        $secret_gmp = self::derive_shared_gmp($our_private_key_gmp, $their_public_key_gmp, $prime_gmp);
        return gmp_strval($secret_gmp, 16);
    }

    /**
     * Make a new random number with a cryptographically safe random number generator
     * @param   int    - The length of the key in bytes
     * @return  string - A Hexadecimal representation of the random number
     */
    public function makeKey( int $length = 32) : string {
        return bin2hex(random_bytes($length));
    }

    /**
     * Make an input vector of the length expected by the currently set algorithm
     * @return string - A Hexadecimal representation of the random number
     */
    public function makeIv() : string {
        return bin2hex(random_bytes( openssl_cipher_iv_length($this->cipher_algorithm) / 2));
    }

    /**
     * Make an Hmac hash of the data and key
     * @return string - A Hexadecimal representation of the hmac
     */
    public function makeHmac(string $data, string $key) : string {
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

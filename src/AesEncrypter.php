<?php
/**
 * File AesEncrypter.php
 */

namespace Tebru\AesEncryption;

use Tebru;
use Tebru\AesEncryption\Enum\AesEnum;
use Tebru\AesEncryption\Exception\InvalidNumberOfEncryptionPieces;
use Tebru\AesEncryption\Exception\IvSizeMismatchException;
use Tebru\AesEncryption\Exception\MacHashMismatchException;

/**
 * Class AesEncrypter
 *
 * @author Nate Brunette <n@tebru.net>
 */
class AesEncrypter
{
    /**#@+
     * Encryption constants
     */
    const ENCRYPTION_CIPHER = MCRYPT_RIJNDAEL_128;
    const ENCRYPTION_MODE = MCRYPT_MODE_CBC;
    /**#@-*/

    /**
     * A secret key
     *
     * @var string
     */
    private $key;

    /**
     * @var string
     */
    private $method;

    /**
     * Constructor
     *
     * @param string $key The secret key
     * @param string $method
     */
    public function __construct($key, $method = AesEnum::METHOD_256)
    {
        $this->key = $key;
        $this->method = $method;
    }

    /**
     * Encrypts any data using mac-then-encrypt method
     *
     * @param mixed $data
     * @return string
     */
    public function encrypt($data)
    {
        $serializedData = serialize($data);
        $iv = $this->createIv();
        $encrypted = $this->createEncrypted($serializedData, $iv);
        $mac = $this->getMac($encrypted);
        $encoded = $this->createEncoded($encrypted, $mac, $iv);

        return $encoded;
    }

    /**
     * Decrypts data encrypted through encrypt() method
     *
     * @param string $data
     * @return mixed
     * @throws IvSizeMismatchException If the IV length has been altered
     * @throws MacHashMismatchException If the data has been altered
     */
    public function decrypt($data)
    {
        // if this is not an encrypted string
        if (false === strpos($data, '|')) {
            return $data;
        }

        list($encryptedData, $mac, $iv) = $this->decodeData($data);

        Tebru\assert($mac === $this->getMac($encryptedData), new MacHashMismatchException('MAC hashes do not match'));
        Tebru\assert(strlen($iv) === $this->getIvSize(), new IvSizeMismatchException('IV size does not match expectation'));

        $serializedData = $this->decryptData($encryptedData, $iv);

        $decrypted = unserialize($serializedData);

        return $decrypted;
    }

    /**
     * Create the IV using mcrypt_create_iv()
     *
     * @return string
     */
    private function createIv()
    {
        return mcrypt_create_iv($this->getIvSize(), MCRYPT_DEV_URANDOM);
    }

    /**
     * Get the size of the IV based on cipher and mode
     *
     * @return int
     */
    private function getIvSize()
    {
        return mcrypt_get_iv_size(self::ENCRYPTION_CIPHER, self::ENCRYPTION_MODE);
    }

    /**
     * Get the key as a packed binary string
     *
     * @return string
     */
    private function getKey()
    {
        // first create a sha256 hash of the key
        $hash = hash('sha256', $this->key);

        // create a binary string from the hash
        $binary = hex2bin($hash);

        // limit the key size based on our encryption method
        $keySize = AesEnum::getKeySize($this->method);
        $key = substr($binary, 0, $keySize);

        return $key;
    }

    /**
     * Get hmac hash of data
     *
     * @param $data
     * @return string
     */
    private function getMac($data)
    {
        return hash_hmac('sha256', $data, $this->getKey());
    }

    /**
     * Encrypt data
     *
     * @param string $data
     * @param string $iv
     * @return string
     */
    private function createEncrypted($data, $iv)
    {
        return mcrypt_encrypt(self::ENCRYPTION_CIPHER, $this->getKey(), $data, self::ENCRYPTION_MODE, $iv);
    }

    /**
     * Encode data/iv using base64 and pipe-delimited
     *
     * @param mixed $encryptedData
     * @param string $mac
     * @param string $iv
     * @return string
     */
    private function createEncoded($encryptedData, $mac, $iv)
    {
        return base64_encode($encryptedData) . '|' . base64_encode($mac) . '|' . base64_encode($iv);
    }

    /**
     * Decodes data/iv and returns array
     *
     * @param string $data
     * @return array
     */
    private function decodeData($data)
    {
        $decoded = explode('|', $data);

        Tebru\assert(3 === sizeof($decoded), new InvalidNumberOfEncryptionPieces('Encrypted string has been modified, wrong number of pieces found'));

        return [base64_decode($decoded[0]), base64_decode($decoded[1]), base64_decode($decoded[2])];
    }

    /**
     * Decrypts data using iv
     *
     * @param mixed $data
     * @param string $iv
     * @return string
     */
    private function decryptData($data, $iv)
    {
        return trim(mcrypt_decrypt(self::ENCRYPTION_CIPHER, $this->getKey(), $data, self::ENCRYPTION_MODE, $iv));
    }
}

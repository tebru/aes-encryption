<?php
/**
 * File AesEncryptionStrategy.php
 */

namespace Tebru\AesEncryption\Strategy;

use Tebru;
use Tebru\AesEncryption\Enum\AesEnum;
use Tebru\AesEncryption\Exception\InvalidNumberOfEncryptionPieces;

/**
 * Class AesEncryptionStrategy
 *
 * @author Nate Brunette <n@tebru.net>
 */
abstract class AesEncryptionStrategy
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
     * Create an initialization vector
     *
     * @return string
     */
    abstract public function createIv();

    /**
     * Get the size of the IV
     *
     * @return int
     */
    abstract public function getIvSize();

    /**
     * Encrypt data
     *
     * @param mixed $data
     * @param string $iv
     * @return mixed
     */
    abstract public function encryptData($data, $iv);

    /**
     * Decrypt data
     *
     * @param $data
     * @param $iv
     * @return mixed
     */
    abstract public function decryptData($data, $iv);

    /**
     * Encode data/iv using base64 and pipe-delimited
     *
     * @param mixed $encryptedData
     * @param string $mac
     * @param string $iv
     * @return string
     */
    public function encodeData($encryptedData, $mac, $iv)
    {
        return base64_encode($encryptedData) . '|' . base64_encode($mac) . '|' . base64_encode($iv);
    }

    /**
     * Decodes data/iv and returns array
     *
     * @param string $data
     * @return array
     */
    public function decodeData($data)
    {
        $decoded = explode('|', $data);

        Tebru\assert(3 === sizeof($decoded), new InvalidNumberOfEncryptionPieces('Encrypted string has been modified, wrong number of pieces found'));

        return [base64_decode($decoded[0]), base64_decode($decoded[1]), base64_decode($decoded[2])];
    }


    /**
     * Get hmac hash of data
     *
     * @param $data
     * @return string
     */
    public function getMac($data)
    {
        return hash_hmac('sha256', $data, $this->getKey());
    }

    /**
     * Get the key as a packed binary string
     *
     * @return string
     */
    protected function getKey()
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
     * Get the encryption method
     *
     * @return string
     */
    protected function getMethod()
    {
        return $this->method;
    }

}

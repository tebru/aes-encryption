<?php
/**
 * File AesEncrypter.php
 */

namespace Tebru\AesEncryption;

use Tebru;
use Tebru\AesEncryption\Enum\CipherEnum;
use Tebru\AesEncryption\Enum\ModeEnum;
use Tebru\AesEncryption\Exception\InvalidKeyException;
use Tebru\AesEncryption\Exception\IvSizeMismatchException;
use Tebru\AesEncryption\Exception\MacHashMismatchException;

/**
 * Class AesEncrypter
 *
 * @author Nate Brunette <n@tebru.net>
 */
class AesEncrypter
{
    /**
     * The allowed key length
     */
    const KEY_LENGTH = 64;

    /**
     * A secret key
     *
     * @var string
     */
    private $key;

    /**
     * The cipher type
     *
     * @var string
     */
    private $cipher;

    /**
     * The encryption mode
     *
     * @var string
     */
    private $mode;

    /**
     * Constructor
     *
     * @param string $key The secret key
     * @param int $blockSize The cipher block size (128, 192, or 256)
     * @param string $mode The encryption mode
     */
    public function __construct($key, $blockSize = CipherEnum::BLOCK_SIZE_128, $mode = ModeEnum::MODE_CBC)
    {
        Tebru\assert(ctype_xdigit($key) && self::KEY_LENGTH === strlen($key), new InvalidKeyException('Key must be a 64 character hexadecimal string'));

        $this->key = $key;
        $this->cipher = CipherEnum::get($blockSize);
        $this->mode = ModeEnum::get($mode);
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
        $mac = $this->getMac($serializedData);
        $encrypted = $this->createEncrypted($serializedData, $mac, $iv);
        $encoded = $this->createEncoded($encrypted, $iv);

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

        list($encryptedData, $iv) = $this->decodeData($data);

        Tebru\assert(strlen($iv) === $this->getIvSize(), new IvSizeMismatchException('IV size does not match expectation'));

        $decryptedWithMac = $this->decryptData($encryptedData, $iv);
        $serializedData = substr($decryptedWithMac, 0, -self::KEY_LENGTH);
        $mac = substr($decryptedWithMac, -self::KEY_LENGTH);

        Tebru\assert($mac === $this->getMac($serializedData), new MacHashMismatchException('MAC hashes do not match'));

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
        return mcrypt_get_iv_size($this->cipher, $this->mode);
    }

    /**
     * Get the key as a packed binary string
     *
     * @return string
     */
    private function getKey()
    {
        return pack('H*', $this->key);
    }

    /**
     * Get hmac hash of data using sha256 and a 32 character key
     *
     * @param $data
     * @return string
     */
    private function getMac($data)
    {
        // make the key 32 characters
        $key = substr(bin2hex($this->getKey()), -(self::KEY_LENGTH / 2));

        return hash_hmac('sha256', $data, $key);
    }

    /**
     * Encrypt data
     *
     * @param string $data
     * @param string $mac
     * @param string $iv
     * @return string
     */
    private function createEncrypted($data, $mac, $iv)
    {
        return mcrypt_encrypt($this->cipher, $this->getKey(), $data . $mac, $this->mode, $iv);
    }

    /**
     * Encode data/iv using base64 and pipe-delimited
     *
     * @param mixed $encryptedData
     * @param string $iv
     * @return string
     */
    private function createEncoded($encryptedData, $iv)
    {
        return base64_encode($encryptedData) . '|' . base64_encode($iv);
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

        return [base64_decode($decoded[0]), base64_decode($decoded[1])];
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
        return trim(mcrypt_decrypt($this->cipher, $this->getKey(), $data, $this->mode, $iv));
    }
}

<?php
/**
 * File McryptStrategy.php
 */

namespace Tebru\AesEncryption\Strategy;

/**
 * Class McryptStrategy
 *
 * @author Nate Brunette <n@tebru.net>
 */
class McryptStrategy extends AesEncryptionStrategy
{
    /**
     * Create an initialization vector
     *
     * @return string
     */
    public function createIv()
    {
        return mcrypt_create_iv($this->getIvSize(), MCRYPT_DEV_URANDOM);
    }

    /**
     * Get the size of the IV
     *
     * @return int
     */
    public function getIvSize()
    {
        return mcrypt_get_iv_size(self::ENCRYPTION_CIPHER, self::ENCRYPTION_MODE);
    }

    /**
     * Encrypt data
     *
     * @param mixed $data
     * @param string $iv
     * @return mixed
     */
    public function encryptData($data, $iv)
    {
        return mcrypt_encrypt(self::ENCRYPTION_CIPHER, $this->getKey(), $data, self::ENCRYPTION_MODE, $iv);
    }

    /**
     * Decrypt data
     *
     * @param $data
     * @param $iv
     * @return mixed
     */
    public function decryptData($data, $iv)
    {
        return trim(mcrypt_decrypt(self::ENCRYPTION_CIPHER, $this->getKey(), $data, self::ENCRYPTION_MODE, $iv));
    }
}

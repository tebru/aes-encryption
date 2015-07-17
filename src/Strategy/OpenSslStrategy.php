<?php
/**
 * File OpenSslStrategy.php
 */

namespace Tebru\AesEncryption\Strategy;

use Tebru\AesEncryption\Enum\AesEnum;

/**
 * Class OpenSslStrategy
 *
 * @author Nate Brunette <n@tebru.net>
 */
class OpenSslStrategy extends AesEncryptionStrategy
{
    /**
     * Create an initialization vector
     *
     * @return string
     */
    public function createIv()
    {
        return openssl_random_pseudo_bytes($this->getIvSize());
    }

    /**
     * Get the size of the IV
     *
     * @return int
     */
    public function getIvSize()
    {
        return openssl_cipher_iv_length($this->getEncryptionMethod());
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
        return openssl_encrypt($data, $this->getEncryptionMethod(), $this->getKey(), true, $iv);
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
        return openssl_decrypt($data, $this->getEncryptionMethod(), $this->getKey(), true, $iv);
    }

    /**
     * Get the openssl formatted encryption method
     *
     * @return string
     */
    private function getEncryptionMethod()
    {
        $keySize = AesEnum::getKeySize($this->getMethod()) * 8;

        return 'aes-' . $keySize . '-' . self::ENCRYPTION_MODE;
    }
}

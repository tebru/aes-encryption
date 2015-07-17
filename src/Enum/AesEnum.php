<?php
/**
 * File AesEnum.php
 */

namespace Tebru\AesEncryption\Enum;

use Tebru\AesEncryption\Exception\InvalidMethodException;

/**
 * Class AesEnum
 *
 * @author Nate Brunette <n@tebru.net>
 */
class AesEnum
{
    const METHOD_128 = 'aes128';
    const METHOD_192 = 'aes192';
    const METHOD_256 = 'aes256';

    /**
     * Get the key size for an encryption method
     *
     * @param $method
     * @return mixed
     */
    public static function getKeySize($method)
    {
        $keySizes = self::getKeySizes();
        if (!in_array($method, array_keys($keySizes), true)) {
            throw new InvalidMethodException(sprintf('Method "%s" is not a valid AES encryption method', $method));
        }

        return $keySizes[$method];
    }

    /**
     * Returns an array keyed by the aes method
     *
     * @return array
     */
    private static function getKeySizes()
    {
        return [
            self::METHOD_128 => 16,
            self::METHOD_192 => 24,
            self::METHOD_256 => 32,
        ];
    }
}

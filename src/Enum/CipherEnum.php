<?php
/**
 * File CipherEnum.php
 */

namespace Tebru\AesEncryption\Enum;

use Tebru\AesEncryption\Exception\InvalidBlockSizeException;

/**
 * Class CipherEnum
 *
 * @author Nate Brunette <n@tebru.net>
 */
class CipherEnum
{
    const BLOCK_SIZE_128 = 128;
    const BLOCK_SIZE_192 = 192;
    const BLOCK_SIZE_256 = 256;

    static public function get($blockSize)
    {
        $blockSizes = self::getBlockSizes();
        if (!in_array($blockSize, array_keys($blockSizes), true)) {
            throw new InvalidBlockSizeException(sprintf('Block size of "%s" is not valid', $blockSize));
        }

        return $blockSizes[$blockSize];
    }

    static private function getBlockSizes()
    {
        return [
            self::BLOCK_SIZE_128 => MCRYPT_RIJNDAEL_128,
            self::BLOCK_SIZE_192 => MCRYPT_RIJNDAEL_192,
            self::BLOCK_SIZE_256 => MCRYPT_RIJNDAEL_256,
        ];
    }
}

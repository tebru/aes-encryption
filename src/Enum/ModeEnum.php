<?php
/**
 * File ModeEnum.php
 */

namespace Tebru\AesEncryption\Enum;

use Tebru\AesEncryption\Exception\InvalidModeException;

/**
 * Class ModeEnum
 *
 * @author Nate Brunette <n@tebru.net>
 */
class ModeEnum
{
    const MODE_CBC = 'cbc';
    const MODE_CFB = 'cfb';
    const MODE_ECB = 'ecb';
    const MODE_NOFB = 'nofb';
    const MODE_OFB = 'ofb';

    static public function get($mode)
    {
        $modes = self::getModes();
        if (!in_array($mode, array_keys($modes))) {
            throw new InvalidModeException(sprintf('Mode "%s" is not a valid mode', $mode));
        }

        return $modes[$mode];
    }

    static private function getModes()
    {
        return [
            self::MODE_CBC => MCRYPT_MODE_CBC,
            self::MODE_CFB => MCRYPT_MODE_CFB,
            self::MODE_ECB => MCRYPT_MODE_ECB,
            self::MODE_NOFB => MCRYPT_MODE_NOFB,
            self::MODE_OFB => MCRYPT_MODE_OFB,
        ];
    }
}

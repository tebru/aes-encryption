<?php
/**
 * File AesEncrypterTest.php
 */

namespace Tebru\AesEncryption\Test;

use PHPUnit_Framework_TestCase;
use Tebru\AesEncryption\AesEncrypter;
use Tebru\AesEncryption\Enum\CipherEnum;
use Tebru\AesEncryption\Enum\ModeEnum;

/**
 * Class AesEncrypterTest
 *
 * @author Nate Brunette <n@tebru.net>
 */
class AesEncrypterTest extends PHPUnit_Framework_TestCase
{
    const TEST_STRING = 'The "quick" brown \'fox\' jumped 0ver the lazy dog!?';

    /**
     * @param $blockSize
     * @param $mode
     *
     * @dataProvider encrypterIterations
     */
    public function testcanEncryptString($blockSize, $mode)
    {
        $this->simpleAssert($blockSize, $mode, self::TEST_STRING);
    }

    /**
     * @param $blockSize
     * @param $mode
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptInteger($blockSize, $mode)
    {
        $this->simpleAssert($blockSize, $mode, 1);
    }

    /**
     * @param $blockSize
     * @param $mode
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptDecimal($blockSize, $mode)
    {
        $this->simpleAssert($blockSize, $mode, 1.9);
    }

    /**
     * @param $blockSize
     * @param $mode
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptBool($blockSize, $mode)
    {
        $this->simpleAssert($blockSize, $mode, false);
    }

    /**
     * @param $blockSize
     * @param $mode
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptNull($blockSize, $mode)
    {
        $this->simpleAssert($blockSize, $mode, null);
    }

    /**
     * @param $blockSize
     * @param $mode
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptArray($blockSize, $mode)
    {
        $this->simpleAssert($blockSize, $mode, ['test' => ['test' => 'test']]);
    }

    /**
     * @param $blockSize
     * @param $mode
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptObject($blockSize, $mode)
    {
        $this->simpleAssert($blockSize, $mode, new \stdClass());
    }

    public function testWillNotDecryptedNonEncryptedString()
    {
        $encrypter = new AesEncrypter($this->generateKey());
        $result = $encrypter->decrypt(null);
        $this->assertEquals(null, $result);
    }

    /**
     * @expectedException \Tebru\AesEncryption\Exception\IvSizeMismatchException
     */
    public function testAlterIvThrowsException()
    {
        $encrypter = new AesEncrypter($this->generateKey());
        $encrypted = $encrypter->encrypt(self::TEST_STRING);
        $encrypted .= '1';
        $result = $encrypter->decrypt($encrypted);
        $this->assertEquals(self::TEST_STRING, $result);
    }

    /**
     * @expectedException \Tebru\AesEncryption\Exception\MacHashMismatchException
     */
    public function testAlterDataThrowsException()
    {
        $encrypter = new AesEncrypter($this->generateKey());
        $encrypted = $encrypter->encrypt(self::TEST_STRING);
        $encrypted = '1' . $encrypted;
        $result = $encrypter->decrypt($encrypted);
        $this->assertEquals(self::TEST_STRING, $result);
    }

    /**
     * @expectedException \Tebru\AesEncryption\Exception\InvalidBlockSizeException
     */
    public function testInvalidBlockSizeThrowsException()
    {
        new AesEncrypter($this->generateKey(), 129);
    }

    public function testKeyWithCharacters()
    {
        $encrypter = new AesEncrypter('!@#$ashYJD56902345&*(_\'"ds6');
        $encrypted = $encrypter->encrypt(self::TEST_STRING);
        $decrypted = $encrypter->decrypt($encrypted);
        $this->assertEquals(self::TEST_STRING, $decrypted);
    }

    /**
     * @expectedException \Tebru\AesEncryption\Exception\InvalidModeException
     */
    public function testInvalidModeThrowsException()
    {
        new AesEncrypter($this->generateKey(), CipherEnum::BLOCK_SIZE_256, 'test');
    }

    private function simpleAssert($blockSize, $mode, $data)
    {
        $encrypter = new AesEncrypter($this->generateKey(), $blockSize, $mode);
        $encrypted = $encrypter->encrypt($data);
        $result = $encrypter->decrypt($encrypted);
        $this->assertEquals($data, $result);
    }

    private function generateKey()
    {
        return bin2hex(openssl_random_pseudo_bytes(mt_rand(0, 100)));
    }

    public function encrypterIterations()
    {
        return [
            [CipherEnum::BLOCK_SIZE_128, ModeEnum::MODE_CBC],
            [CipherEnum::BLOCK_SIZE_128, ModeEnum::MODE_CFB],
            [CipherEnum::BLOCK_SIZE_128, ModeEnum::MODE_ECB],
            [CipherEnum::BLOCK_SIZE_128, ModeEnum::MODE_NOFB],
            [CipherEnum::BLOCK_SIZE_128, ModeEnum::MODE_OFB],
            [CipherEnum::BLOCK_SIZE_192, ModeEnum::MODE_CBC],
            [CipherEnum::BLOCK_SIZE_192, ModeEnum::MODE_CFB],
            [CipherEnum::BLOCK_SIZE_192, ModeEnum::MODE_ECB],
            [CipherEnum::BLOCK_SIZE_192, ModeEnum::MODE_NOFB],
            [CipherEnum::BLOCK_SIZE_192, ModeEnum::MODE_OFB],
            [CipherEnum::BLOCK_SIZE_256, ModeEnum::MODE_CBC],
            [CipherEnum::BLOCK_SIZE_256, ModeEnum::MODE_CFB],
            [CipherEnum::BLOCK_SIZE_256, ModeEnum::MODE_ECB],
            [CipherEnum::BLOCK_SIZE_256, ModeEnum::MODE_NOFB],
            [CipherEnum::BLOCK_SIZE_256, ModeEnum::MODE_OFB],
        ];
    }
}

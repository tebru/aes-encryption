<?php
/**
 * File AesEncrypterTest.php
 */

namespace Tebru\AesEncryption\Test;

use PHPUnit_Framework_TestCase;
use Tebru\AesEncryption\AesEncrypter;
use Tebru\AesEncryption\Enum\AesEnum;

/**
 * Class AesEncrypterTest
 *
 * @author Nate Brunette <n@tebru.net>
 */
class AesEncrypterTest extends PHPUnit_Framework_TestCase
{
    const TEST_STRING = 'The "quick" brown \'fox\' jumped 0ver the lazy dog!?';

    /**
     * @param $method
     *
     * @dataProvider encrypterIterations
     */
    public function testcanEncryptString($method)
    {
        $this->simpleAssert($method, self::TEST_STRING);
    }

    /**
     * @param $method
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptInteger($method)
    {
        $this->simpleAssert($method, 1);
    }

    /**
     * @param $method
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptDecimal($method)
    {
        $this->simpleAssert($method, 1.9);
    }

    /**
     * @param $method
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptBool($method)
    {
        $this->simpleAssert($method, false);
    }

    /**
     * @param $method
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptNull($method)
    {
        $this->simpleAssert($method, null);
    }

    /**
     * @param $method
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptArray($method)
    {
        $this->simpleAssert($method, ['test' => ['test' => 'test']]);
    }

    /**
     * @param $method
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptObject($method)
    {
        $this->simpleAssert($method, new \stdClass());
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

    public function testKeyWithCharacters()
    {
        $encrypter = new AesEncrypter('!@#$ashYJD56902345&*(_\'"ds6');
        $encrypted = $encrypter->encrypt(self::TEST_STRING);
        $decrypted = $encrypter->decrypt($encrypted);
        $this->assertEquals(self::TEST_STRING, $decrypted);
    }

    /**
     * @expectedException \Tebru\AesEncryption\Exception\InvalidMethodException
     */
    public function testInvalidMethodThrowsException()
    {
        $encrypter = new AesEncrypter($this->generateKey(), 'test');
        $encrypter->encrypt('test');
    }

    private function simpleAssert($method, $data)
    {
        $encrypter = new AesEncrypter($this->generateKey(), $method);
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
            [AesEnum::METHOD_128],
            [AesEnum::METHOD_192],
            [AesEnum::METHOD_256],
        ];
    }
}

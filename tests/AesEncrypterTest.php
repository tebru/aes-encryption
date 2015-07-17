<?php
/**
 * File AesEncrypterTest.php
 */

namespace Tebru\AesEncryption\Test;

use PHPUnit_Framework_TestCase;
use Tebru\AesEncryption\AesEncrypter;
use Tebru\AesEncryption\Enum\AesEnum;
use Tebru\AesEncryption\Strategy\OpenSslStrategy;

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
     * @param $strategy
     *
     * @dataProvider encrypterIterations
     */
    public function testcanEncryptString($method, $strategy)
    {
        $this->simpleAssert($method, $strategy, self::TEST_STRING);
    }

    /**
     * @param $method
     * @param $strategy
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptInteger($method, $strategy)
    {
        $this->simpleAssert($method, $strategy, 1);
    }

    /**
     * @param $method
     * @param $strategy
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptDecimal($method, $strategy)
    {
        $this->simpleAssert($method, $strategy, 1.9);
    }

    /**
     * @param $method
     * @param $strategy
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptBool($method, $strategy)
    {
        $this->simpleAssert($method, $strategy, false);
    }

    /**
     * @param $method
     * @param $strategy
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptNull($method, $strategy)
    {
        $this->simpleAssert($method, $strategy, null);
    }

    /**
     * @param $method
     * @param $strategy
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptArray($method, $strategy)
    {
        $this->simpleAssert($method, $strategy, ['test' => ['test' => 'test']]);
    }

    /**
     * @param $method
     * @param $strategy
     *
     * @dataProvider encrypterIterations
     */
    public function testCanEncryptObject($method, $strategy)
    {
        $this->simpleAssert($method, $strategy, new \stdClass());
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

    public function testWillUseOpenSslByDefault()
    {
        $encrypter = new AesEncrypter($this->generateKey());

        $this->assertAttributeInstanceOf(OpenSslStrategy::class, 'strategy', $encrypter);
    }

    private function simpleAssert($method, $strategy, $data)
    {
        $encrypter = new AesEncrypter($this->generateKey(), $method, $strategy);
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
            [AesEnum::METHOD_128, AesEncrypter::STRATEGY_OPENSSL],
            [AesEnum::METHOD_192, AesEncrypter::STRATEGY_OPENSSL],
            [AesEnum::METHOD_256, AesEncrypter::STRATEGY_OPENSSL],
            [AesEnum::METHOD_128, AesEncrypter::STRATEGY_MCRYPT],
            [AesEnum::METHOD_192, AesEncrypter::STRATEGY_MCRYPT],
            [AesEnum::METHOD_256, AesEncrypter::STRATEGY_MCRYPT],
        ];
    }
}

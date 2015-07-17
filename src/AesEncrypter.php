<?php
/**
 * File AesEncrypter.php
 */

namespace Tebru\AesEncryption;

use Tebru;
use Tebru\AesEncryption\Enum\AesEnum;
use Tebru\AesEncryption\Exception\IvSizeMismatchException;
use Tebru\AesEncryption\Exception\MacHashMismatchException;
use Tebru\AesEncryption\Strategy\AesEncryptionStrategy;
use Tebru\AesEncryption\Strategy\McryptStrategy;
use Tebru\AesEncryption\Strategy\OpenSslStrategy;

/**
 * Class AesEncrypter
 *
 * @author Nate Brunette <n@tebru.net>
 */
class AesEncrypter
{
    const STRATEGY_OPENSSL = 'openssl';
    const STRATEGY_MCRYPT = 'mcrypt';

    /**
     * @var AesEncryptionStrategy
     */
    private $strategy;

    /**
     * Constructor
     *
     * @param string $key The secret key
     * @param string $method
     * @param AesEncryptionStrategy $strategy
     */
    public function __construct($key, $method = AesEnum::METHOD_256, $strategy = null)
    {
        if (null === $strategy) {
            // use openssl if it exists
            $strategy = (function_exists('openssl_encrypt'))
                ? new OpenSslStrategy($key, $method)
                : new McryptStrategy($key, $method);
        } else {
            $strategy = (self::STRATEGY_OPENSSL === $strategy)
                ? new OpenSslStrategy($key, $method)
                : new McryptStrategy($key, $method);
        }

        $this->strategy = $strategy;
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
        $iv = $this->strategy->createIv();
        $encrypted = $this->strategy->encryptData($serializedData, $iv);
        $mac = $this->strategy->getMac($encrypted);
        $encoded = $this->strategy->encodeData($encrypted, $mac, $iv);

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

        list($encryptedData, $mac, $iv) = $this->strategy->decodeData($data);

        Tebru\assert($mac === $this->strategy->getMac($encryptedData), new MacHashMismatchException('MAC hashes do not match'));
        Tebru\assert(strlen($iv) === $this->strategy->getIvSize(), new IvSizeMismatchException('IV size does not match expectation'));

        $serializedData = $this->strategy->decryptData($encryptedData, $iv);

        $decrypted = unserialize($serializedData);

        return $decrypted;
    }
}

<?php

namespace P5ych0\Laracrypt\Tests;

use RuntimeException;
use P5ych0\Laracrypt\SSL;
use Illuminate\Contracts\Encryption\DecryptException;

/**
 * Class     SSLTest
 */
class SSLTest extends TestCase
{
    /* ------------------------------------------------------------------------------------------------
     |  Properties
     | ------------------------------------------------------------------------------------------------
     */

    /**
     * @var \P5ych0\Laracrypt\SSL
     */
    private $obf;

    /* ------------------------------------------------------------------------------------------------
     |  Main Functions
     | ------------------------------------------------------------------------------------------------
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->obf = $this->app["encrypt.ssl"];
        $this->obf->setOwner("testing");
    }

    public function tearDown(): void
    {
        unset($this->obf);

        parent::tearDown();
    }

    /* ------------------------------------------------------------------------------------------------
     |  Test Functions
     | ------------------------------------------------------------------------------------------------
     */

    public function testItCanBeInstantiated()
    {
        $this->assertInstanceOf(SSL::class, $this->obf);
    }

    public function testItCanEncryptString()
    {
        $str = $this->obf->encrypt("string");

        $this->assertIsString($str);
    }

    public function testItCanEncryptScalar()
    {
        $str = $this->obf->encrypt(12345);

        $this->assertIsString($str);
    }

    public function testItCanEncryptArray()
    {
        $str = $this->obf->encrypt(["my" => "array", [1, 2, 3]]);

        $this->assertIsString($str);
    }

    /**
     * @dataProvider decryptionProvider
     * @param mixed $v
     */
    public function testItCanDecrypt($v)
    {
        $e = $this->obf->encrypt($v);

        $this->assertSame($v, $this->obf->decrypt($e));
    }

    public function testItMustThrowCantEncrypt()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Can't open private key");
        $ssl = new SSL;

        $ssl->encrypt(false);
    }

    public function testItMustThrowCantDecrypt()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage("Cannot be processed");

        $this->obf->decrypt("weird");
    }

    public function testItMusThrowFailedDecrypt()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage("Failed to decrypt data");

        $this->obf->decrypt("TWVldCBCYXNlNjQgRGVjb2RlIGFuZCBFbmNvZGUsIGEgc2ltcGxlIG9ubGluZSB0b29sIHRoYXQgZG9lcyBleGFjdGx5IHdoYXQgaXQgc2F5czsgZGVjb2RlcyBCYXNlNjQgZW5jb2RpbmcgYW5kIGVuY29kZXMgaW50byBpdCBxdWlja2x5IGFuZCBlYXNpbHkuIEJhc2U2NCBlbmNvZGUgeW91ciBkYXRhIGluIGEgaGFzc2xlLWZyZWUgd2F5LCBvciBkZWNvZGUgaXQgaW50byBodW1hbi1yZWFkYWJsZSBmb3JtYXQu");
    }

    public function decryptionProvider()
    {
        return array_map(function($item) { return [$item]; }, [
            ["my" => "array", [1, 2, 3], true],
            "string",
            1234,
            null,
        ]);
    }
}

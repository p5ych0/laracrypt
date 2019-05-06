<?php

namespace P5ych0\Laracrypt\Tests;

use P5ych0\Laracrypt\Aes256;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\DecryptException;

/**
 * Class     WebSafeTest
 */
class WebSafeTest extends TestCase
{
    /* ------------------------------------------------------------------------------------------------
     |  Properties
     | ------------------------------------------------------------------------------------------------
     */

    /**
     * @var \P5ych0\Laracrypt\Aes256
     */
    private $obf;

    /* ------------------------------------------------------------------------------------------------
     |  Main Functions
     | ------------------------------------------------------------------------------------------------
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->obf = new Aes256($this->config["key"], $this->config["cipher"]);
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

    public function testIt_can_be_instantiated()
    {
        $this->assertInstanceOf(Aes256::class, $this->obf);
    }

    public function testIt_can_encrypt_string()
    {
        $str = $this->obf->encrypt("string");

        $this->assertIsString($str);
    }

    public function testIt_can_encrypt_scalar()
    {
        $str = $this->obf->encrypt(12345);

        $this->assertIsString($str);
    }

    public function testIt_can_encrypt_array()
    {
        $str = $this->obf->encrypt(["my" => "array", [1, 2, 3]]);

        $this->assertIsString($str);
    }

    /**
     * @dataProvider decryptionProvider
     * @param mixed $v
     */
    public function testIt_can_decrypt($v)
    {
        $e = $this->obf->encrypt($v);

        $this->assertSame($v, $this->obf->decrypt($e));
    }

    public function testIt_must_throw_cant_encrypt()
    {
        $this->expectException(EncryptException::class);
        $this->expectExceptionMessage("Can't encrypt FALSE");

        $this->obf->encrypt(false);
    }

    public function testIt_must_throw_cant_decrypt()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage("Can't decrypt");

        $this->obf->decrypt("weird");
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

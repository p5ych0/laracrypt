<?php

namespace P5ych0\Laracrypt\Tests;

use P5ych0\Laracrypt\Feistel;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\DecryptException;

/**
 * Class     SerialTest
 */
class SerialTest extends TestCase
{
    /* ------------------------------------------------------------------------------------------------
     |  Properties
     | ------------------------------------------------------------------------------------------------
     */

    /**
     * @var \P5ych0\Laracrypt\Feistel
     */
    private $obf;

    /* ------------------------------------------------------------------------------------------------
     |  Main Functions
     | ------------------------------------------------------------------------------------------------
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->obf = new Feistel($this->config["fmode"], $this->config["fmask"], $this->config["fkey"]);
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
        $this->assertInstanceOf(Feistel::class, $this->obf);
    }

    public function testIt_can_encrypt_int()
    {
        $str = $this->obf->encrypt(1);

        $this->assertRegExp("#^[A-Z]{3}\s+\d{8}$#", $str);
    }

    public function testIt_cant_encrypt_non_int()
    {
        $this->expectException(EncryptException::class);
        $this->expectExceptionMessage("Value must be positive integer");

        $this->obf->encrypt("string");
    }

    public function testIt_cant_encrypt_non_positive()
    {
        $this->expectException(EncryptException::class);
        $this->expectExceptionMessage("Value must be positive integer");

        $this->obf->encrypt(-123450);
    }

    public function testIt_cant_encrypt_zero()
    {
        $this->expectException(EncryptException::class);
        $this->expectExceptionMessage("Value must be positive integer");

        $this->obf->encrypt(0);
    }

    public function testIt_cant_encrypt_big()
    {
        $this->expectException(EncryptException::class);
        $this->expectExceptionMessage("Value must be lesser than or equal to 68719476735");

        $this->obf->encrypt(68719476736);
    }

    public function testIt_should_return_max()
    {
        $chars = $this->obf->getMax(true);
        $val   = $this->obf->getMax(false);
        $power = $this->obf->getMax(null);

        $this->assertSame(11, $chars);
        $this->assertSame(68719476735, $val);
        $this->assertSame(36, $power);
    }

    /**
     * @dataProvider decryptionProvider
     * @param mixed $v
     */
    public function testIt_can_decrypt($v)
    {
        $e = $this->obf->encrypt($v);

        $this->assertSame($this->obf->decrypt($e), $v);
    }

    public function testIt_must_throw_cant_decrypt()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage("Malformed input");

        $this->obf->decrypt("weird");
    }

    public function decryptionProvider()
    {
        return array_map(function($item) { return [$item]; }, [
            1,
            100,
            56787654,
            68719476735,
        ]);
    }
}

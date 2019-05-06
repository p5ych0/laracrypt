<?php

namespace P5ych0\Laracrypt\Tests;

use P5ych0\Laracrypt\UUID;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\DecryptException;

/**
 * Class     UUIDTest
 */
class UUIDTest extends TestCase
{
    /* ------------------------------------------------------------------------------------------------
     |  Properties
     | ------------------------------------------------------------------------------------------------
     */

    /**
     * @var \P5ych0\Laracrypt\UUID
     */
    private $obf;

    /* ------------------------------------------------------------------------------------------------
     |  Main Functions
     | ------------------------------------------------------------------------------------------------
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->obf = new UUID($this->config["cipher"], $this->config["pass"], $this->config["iv"]);
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
        $this->assertInstanceOf(UUID::class, $this->obf);
    }

    public function testIt_can_encrypt_int()
    {
        $str = $this->obf->encrypt(165834549);

        $this->assertTrue(is_uuid($str));
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

    /**
     * @dataProvider decryptionProvider
     * @param mixed $v
     */
    public function testIt_can_decrypt($v)
    {
        $e = $this->obf->encrypt(...array_values($v));

        $this->assertSame($this->obf->decrypt($e), $v);
    }

    public function testIt_must_throw_cant_decrypt()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage("Can't decrypt int");

        $this->obf->decrypt("45f160b5-9320-621e-f911-c909ff126ea9");
    }

    public function testIt_must_throw_malformed()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage("Malformed input");

        $this->obf->decrypt("weird");
    }

    public function decryptionProvider()
    {
        return [
            [[
                "id"    => 1,
                "value" => 1234,
                "owner" => 0,
                "flag"  => 0,
            ]], [[
                "id"    => 100,
                "value" => -43234,
                "owner" => 0,
                "flag"  => 0,
            ]], [[
                "id"    => 56787654,
                "value" => 0,
                "owner" => 230,
                "flag"  => 1,
            ]], [[
                "id"    => 68719476735,
                "value" => 0,
                "owner" => 0,
                "flag"  => 50,
            ]], [[
                "id"    => 212765935319097,
                "value" => 0,
                "owner" => 12,
                "flag"  => 0,
            ]], [[
                "id"    => PHP_INT_MAX,
                "value" => 0,
                "owner" => 2,
                "flag"  => 2,
            ]],
        ];
    }
}

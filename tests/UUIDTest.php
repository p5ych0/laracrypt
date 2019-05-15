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

        $this->obf = $this->app["obfuscate.uuid"];
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
        $this->assertInstanceOf(UUID::class, $this->obf);
    }

    public function testFacadeWorks()
    {
        \UUIDPretender::shouldReceive("encrypt")->once()->with(1, 1, 1, 1);
        \UUIDPretender::encrypt(1, 1, 1, 1);
    }

    public function testItCanEncryptInt()
    {
        $str = $this->obf->encrypt(165834549);

        $this->assertTrue(is_uuid($str));
    }

    public function testItCantEncryptNonInt()
    {
        $this->expectException(EncryptException::class);
        $this->expectExceptionMessage("Value must be positive integer");

        $this->obf->encrypt("string");
    }

    public function testItCantEncryptNonPositive()
    {
        $this->expectException(EncryptException::class);
        $this->expectExceptionMessage("Value must be positive integer");

        $this->obf->encrypt(-123450);
    }

    public function testItCantEncryptZero()
    {
        $this->expectException(EncryptException::class);
        $this->expectExceptionMessage("Value must be positive integer");

        $this->obf->encrypt(0);
    }

    /**
     * @dataProvider decryptionProvider
     * @param mixed $v
     */
    public function testItCanDecrypt($v)
    {
        $e = $this->obf->encrypt(...array_values($v));

        $this->assertSame($this->obf->decrypt($e), $v);
    }

    public function testItMustThrowCantDecrypt()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage("Can't decrypt int");

        $this->obf->decrypt("45f160b5-9320-621e-f911-c909ff126ea9");
    }

    public function testItMustThrowMalformed()
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

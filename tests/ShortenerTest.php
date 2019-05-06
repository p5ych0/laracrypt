<?php

namespace P5ych0\Laracrypt\Tests;

use P5ych0\Laracrypt\Shortener;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\DecryptException;

/**
 * Class     ShortenerTest
 */
class ShortenerTest extends TestCase
{
    /* ------------------------------------------------------------------------------------------------
     |  Properties
     | ------------------------------------------------------------------------------------------------
     */

    /**
     * @var \P5ych0\Laracrypt\Shortener
     */
    private $obf;

    /* ------------------------------------------------------------------------------------------------
     |  Main Functions
     | ------------------------------------------------------------------------------------------------
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->obf = new Shortener($this->config["chars"], $this->config["simple"], $this->config["add"]);
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
        $this->assertInstanceOf(Shortener::class, $this->obf);
    }

    public function testIt_can_encrypt_int()
    {
        $str = $this->obf->encrypt(165834549);

        $this->assertRegExp("#^[{$this->config["chars"]}]{3,10}$#", $str);
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
        $this->expectExceptionMessage("Value must be lesser than or equal to 212765935319097");

        $this->obf->encrypt(212765935319098);
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
        $this->expectExceptionMessage("Can't deobfuscate value");

        $this->obf->decrypt("weird");
    }

    public function testIt_must_throw_malformed()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage("Malformed input");

        $this->obf->decrypt("Zhjkfsd");
    }

    public function decryptionProvider()
    {
        return array_map(function($item) { return [$item]; }, [
            1,
            100,
            56787654,
            68719476735,
            212765935319097,
        ]);
    }
}

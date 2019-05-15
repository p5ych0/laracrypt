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

        $this->obf = $this->app["obfuscate.shortener"];
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
        $this->assertInstanceOf(Shortener::class, $this->obf);
    }

    public function testFacadeWorks()
    {
        \Shortener::shouldReceive("encrypt")->once()->with(1);
        \Shortener::encrypt(1);
    }

    public function testItCanEncryptInt()
    {
        $str = $this->obf->encrypt(165834549);

        $this->assertRegExp("#^[{$this->app["config"]->get("obfuscator.chars")}]{3,10}$#", $str);
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

    public function testItCantEncryptBig()
    {
        $this->expectException(EncryptException::class);
        $this->expectExceptionMessage("Value must be lesser than or equal to 212765935319097");

        $this->obf->encrypt(212765935319098);
    }

    /**
     * @dataProvider decryptionProvider
     * @param mixed $v
     */
    public function testItCanDecrypt($v)
    {
        $e = $this->obf->encrypt($v);

        $this->assertSame($this->obf->decrypt($e), $v);
    }

    public function testItMustThrowCantDecrypt()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage("Can't deobfuscate value");

        $this->obf->decrypt("weird");
    }

    public function testItMustThrowMalformed()
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

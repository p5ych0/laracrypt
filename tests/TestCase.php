<?php

namespace P5ych0\Laracrypt\Tests;

use PHPUnit\Framework\TestCase as BaseTestCase;

/**
 * Class     TestCase
 */
abstract class TestCase extends BaseTestCase
{
    /* ------------------------------------------------------------------------------------------------
     |  Properties
     | ------------------------------------------------------------------------------------------------
     */
    protected $config = [
        "cipher" => "AES-256-CBC",

        "key"    => "\x00\x90\x77\xca\x00\x00\xd4\x6d\x91\x5e\x8f\x4e\x66\x0d\x03\x46\x53\xce\x60\x37\x09\x75\x10\xb2\xad\x5e\x4a\x49\xdb\x5b\x5f\x99",
        "pass"   => "c6cf675c7cd99d8ae277b4eec48df1f7522916d53517343add3c9b779131cbc5",
        "iv"     => "0f64f9aff4f62c27",

        "chars"  => "CB1Aqayku37HspzE8olFgmxvjhdDw04962frcnbet5i",
        "simple" => 47,
        "add"    => 2341,

        "fkey"   => 0xDC1FA093,
        "fmode"  => true,
        "fmask"  => 0x3FFFF,
    ];
}

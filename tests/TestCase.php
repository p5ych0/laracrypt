<?php

namespace P5ych0\Laracrypt\Tests;

use Orchestra\Testbench\TestCase as BaseTest;

/**
 * Base test case
 */
abstract class TestCase extends BaseTest
{
    /**
     * Get package providers.
     *
     * @param \Illuminate\Foundation\Application $app
     *
     * @return array
     */
    protected function getPackageProviders($app)
    {
        return [
            \P5ych0\Laracrypt\ObfuscationServiceProvider::class,
        ];
    }

    /**
     * Get package aliases.
     *
     * @param \Illuminate\Foundation\Application $app
     *
     * @return array
     */
    protected function getPackageAliases($app)
    {
        return [
            "WebSafe"       => \P5ych0\Laracrypt\Facades\Aes256::class,
            "Shortener"     => \P5ych0\Laracrypt\Facades\Shortener::class,
            "UUIDPretender" => \P5ych0\Laracrypt\Facades\UUID::class,
            "SerialNumber"  => \P5ych0\Laracrypt\Facades\Serial::class,
        ];
    }

    /**
     * Define environment setup.
     *
     * @param \Illuminate\Foundation\Application $app
     */
    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set("obfuscator.cipher", "AES-256-CBC");
        $app['config']->set("obfuscator.key", "\x00\x90\x77\xca\x00\x00\xd4\x6d\x91\x5e\x8f\x4e\x66\x0d\x03\x46\x53\xce\x60\x37\x09\x75\x10\xb2\xad\x5e\x4a\x49\xdb\x5b\x5f\x99");
        $app['config']->set("obfuscator.pass", "c6cf675c7cd99d8ae277b4eec48df1f7522916d53517343add3c9b779131cbc5");
        $app['config']->set("obfuscator.iv", "0f64f9aff4f62c27");
        $app['config']->set("obfuscator.chars", "CB1Aqayku37HspzE8olFgmxvjhdDw04962frcnbet5i");
        $app['config']->set("obfuscator.simple", 47);
        $app['config']->set("obfuscator.add", 2341);
        $app['config']->set("obfuscator.fkey", 0xDC1FA093);
        $app['config']->set("obfuscator.fmode", true);
        $app['config']->set("obfuscator.fmask", 0x3FFFF);
    }
}

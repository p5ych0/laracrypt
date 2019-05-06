<?php

namespace P5ych0\Laracrypt\Tests;

use Orchestra\Testbench\TestCase as BaseTestCase;

/**
 * Class     LaravelTestCase
 */
abstract class LaravelTestCase extends BaseTestCase
{
    /* ------------------------------------------------------------------------------------------------
     |  Other Functions
     | ------------------------------------------------------------------------------------------------
     */

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
//        return [
//            'Obfuscator' => \P5ych0\Laracrypt\Facades\Obfuscator::class
//        ];
    }

    /**
     * Define environment setup.
     *
     * @param \Illuminate\Foundation\Application $app
     */
    protected function getEnvironmentSetUp($app)
    {
    }
}

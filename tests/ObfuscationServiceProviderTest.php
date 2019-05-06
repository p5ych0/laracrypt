<?php

namespace P5ych0\Laracrypt\Tests;

use P5ych0\Laracrypt\ObfuscationServiceProvider;

/**
 * Class     ObfuscationrServiceProviderTest
 */
class ObfuscationServiceProviderTest extends LaravelTestCase
{
    /* ------------------------------------------------------------------------------------------------
     |  Properties
     | ------------------------------------------------------------------------------------------------
     */

    /** @var \P5ych0\Laracrypt\ObfuscationServiceProvider */
    private $provider;

    /* ------------------------------------------------------------------------------------------------
     |  Main Functions
     | ------------------------------------------------------------------------------------------------
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->provider = $this->app->getProvider(ObfuscationServiceProvider::class);
    }

    public function tearDown(): void
    {
        unset($this->provider);

        parent::tearDown();
    }

    /* ------------------------------------------------------------------------------------------------
     |  Test Functions
     | ------------------------------------------------------------------------------------------------
     */

    public function testIt_can_provides()
    {
        $expected = ["obfuscate.uuid", "obfuscate.shortener", "encrypt.websafe", "obfuscate.serial", "encrypt.ssl"];

        $this->assertEquals($expected, $this->provider->provides());
    }
}

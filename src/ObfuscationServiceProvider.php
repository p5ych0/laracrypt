<?php

namespace P5ych0\Laracrypt;

use RuntimeException;
use Illuminate\Support\Str;
use Illuminate\Support\ServiceProvider;

class ObfuscationServiceProvider extends ServiceProvider
{
    protected $defer = true;

    /**
     * {@inheritdoc}
     */
    public function boot()
    {
        $this->publishes([
            __DIR__ . "/config/obfuscator.php" => config_path("obfuscator.php"),
        ], "config");

        $this->commands([
            SecureObfuscator::class,
        ]);
    }

    /**
     * Register the service provider
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . "/config/obfuscator.php", "obfuscator");

        $config = $this->app->make("config")->get("obfuscator");

        $this->app->singleton("obfuscate.uuid", function() use ($config) {
            return new UUID($config["cipher"], $config["pass"], $config["iv"]);
        });

        $this->app->singleton("obfuscate.shortener", function() use ($config) {
            return new Shortener($config["chars"], $config["simple"], $config["add"]);
        });

        $this->app->singleton("encrypt.websafe", function() use ($config) {
            if (Str::startsWith($key = $this->key($config), 'base64:')) {
                $key = base64_decode(substr($key, 7), true);
            }

            return new Aes256($key, $config["cipher"]);
        });

        $this->app->singleton("obfuscate.serial", function() use ($config) {
            return new Feistel($config["fmode"], $config["fmask"], $config["fkey"]);
        });

        $this->app->singleton("encrypt.ssl", function() {
            return new SSL;
        });
    }

    /**
     * {@inheritdoc}
     */
    public function provides()
    {
        return ["obfuscate.uuid", "obfuscate.shortener", "encrypt.websafe", "obfuscate.serial", "encrypt.ssl"];
    }

    /**
     * Extract the encryption key from the given configuration.
     *
     * @param  array  $config
     * @return string
     */
    protected function key(array $config)
    {
        return tap($config['key'], function($key) {
            if (empty($key)) {
                throw new RuntimeException(
                    'No application encryption key has been specified.'
                );
            }
        });
    }
}

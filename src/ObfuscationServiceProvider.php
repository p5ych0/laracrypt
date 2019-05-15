<?php

/*
 * The MIT License
 *
 * Copyright 2019 Kostiantyn Karnasevych <constantine.karnacevych@gmail.com>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

namespace P5ych0\Laracrypt;

use RuntimeException;
use Illuminate\Support\Str;
use Illuminate\Support\ServiceProvider;

/**
 * Service Provider for (de) obfuscation/encryption functionality designed for Laravel
 *
 * @author Kostiantyn Karnasevych <constantine.karnacevych@gmail.com>
 */
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

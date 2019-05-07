<?php

namespace P5ych0\Laracrypt;

use Exception;
use Illuminate\Console\Command;
use Illuminate\Console\ConfirmableTrait;

class SecureObfuscator extends Command
{
    use ConfirmableTrait;
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = "obfuscator:install {--f|force : Force update secure keys}";

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = "Set security keys for obfuscator";

    /**
     * @var bool
     */
    protected $force = false;

    protected $keys = [
        "key"    => "APP_KEY",
        "pass"   => "OBFUSCATOR_PASS",
        "iv"     => "OBFUSCATOR_IV",
        "chars"  => "OBFUSCATOR_CHARS",
        "simple" => "OBFUSCATOR_SIMPLE",
        "add"    => "OBFUSCATOR_ADD",
        "fmode"  => "FEISTEL_MODE",
        "fmask"  => "FEISTEL_MASK",
        "fkey"   => "FEISTEL_KEY",
        "ssl"    => "SSL_ENCRYPTION",
    ];

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $envFilePath = app()->environmentFilePath();
        $contents    = file_get_contents($envFilePath);
        $init        = null;

        foreach ($this->keys as $section => $key) {
            $old = $this->getOldValue($contents, $key);

            if ($this->confirmToProceed()) {
                if (empty($old) || !empty($old) && $this->confirm("Would you like to replace $key=$old?")) {
                    $init = $this->{"createNew" . ucfirst($section)}($init);
                }
            }
        }
    }

    protected function createNewKey()
    {
        $this->call("key:generate");
    }

    protected function createNewPass()
    {
        if ($this->confirm("Do you want to enter a password?")) {
            $inp = $this->ask("New password: ");
        } else {
            $inp = microtime(true);
        }

        $this->call("env:set", ["key" => "obfuscator_pass", "value" => hash("sha256", $inp)]);
    }

    protected function createNewIv()
    {
        if ($this->confirm("Do you want to enter a phrase for IV?")) {
            $inp = $this->ask("New phrase: ");
        } else {
            $inp = microtime(true);
        }

        $this->call("env:set", ["key" => "obfuscator_iv", "value" => substr(hash("sha256", $inp), 0, 16)]);
    }

    protected function createNewChars()
    {
        $inp = $this->ask("Please enter a set of chars to use with shortener", "0123456789ABCDEFHabcdefghijklmnopqrstuvwxyz");

        $this->call("env:set", ["key" => "obfuscator_chars", "value" => str_shuffle($inp)]);
    }

    protected function createNewSimple()
    {
        $this->info("The bigger the number the longer the initial value");

        $inp = 46;

        while (!is_prime($inp)) {
            $inp = (int) ($this->ask("Please enter a prime number to use with shortener", next_prime($inp)));

            if ($inp < 47) {
                $this->alert("Number must be greater or equal to 47");
                $inp = 46;
            }
        }

        $this->call("env:set", ["key" => "obfuscator_simple", "value" => $inp]);
    }

    protected function createNewAdd()
    {
        $this->info("The bigger the number the longer the initial value");

        $good = false;

        $inp = 2000;

        while (!$good) {
            $inp = (int) ($this->ask("Please enter a prime number to use with shortener", next_prime($inp)));

            if ($inp <= 2000) {
                $this->alert("Number must be greater than 2000");
                $inp = 2000;
            } elseif (!is_prime($inp)) {
                $good = $this->confirm("The number you entered is not prime. Are you sure?");
            } else {
                $good = true;
            }
        }

        $this->call("env:set", ["key" => "obfuscator_add", "value" => $inp]);
    }

    protected function createNewFmode()
    {
        $inp = $this->confirm("Use letter in serial numbers", true);

        $this->call("env:set", ["key" => "feistel_mode", "value" => $inp ? "true" : "false"]);
    }

    protected function createNewFmask()
    {
        $mask = "3FFFF";

        $good = false;

        while ($good === false) {
            $mask = strtoupper($this->ask("Add mask to serial numbers", $mask));

            try {
                if (!preg_match("#^[137F]F*$#", $mask)) {
                    throw new Exception("Mask valid regexp is [137F]F*");
                }

                $im = hexdec($mask);

                if ($im < 3) {
                    throw new Exception("The mask cannot be lesser than 03");
                }

                if ($im > 0x7fffffff) {
                    throw new Exception("The mask should not be greater than 7FFFFFFF");
                }

                $good = true;
            } catch (Exception $e) {
                $this->alert($e->getMessage());
            }
        }

        $this->call("env:set", ["key" => "feistel_mask", "value" => $im]);

        return $im;
    }

    protected function createNewFkey($mask)
    {
        $key    = "DC1FA093";
        $min    = ($mask + 1) / 2 - 1;
        $minHex = strtoupper(dechex($min));

        $good = false;

        while ($good === false) {
            $key = strtoupper($this->ask("Add key to serial numbers", $key));

            try {
                $im = hexdec($key);

                if ($im <= 0) {
                    throw new RuntimeException("Key is invalid");
                }

                if ($im <= $min) {
                    throw new RuntimeException("Can't operate with such a short key " . $key . ". Value must be greater than " . $minHex);
                }

                $good = true;
            } catch (Exception $e) {
                $this->alert($e->getMessage());
            }
        }

        $this->call("env:set", ["key" => "feistel_key", "value" => $im]);
    }

    protected function createNewSsl()
    {
        $inp = $this->confirm("Use SSL encryption", true);

        $this->call("env:set", ["key" => "ssl_encryption", "value" => $inp ? "true" : "false"]);
    }

    /**
     * Get the old value of a given key from an environment file.
     *
     * @param  string $envFile
     * @param  string $key
     * @return string
     */
    protected function getOldValue(string $envFile, string $key): string
    {
        // Match the given key at the beginning of a line
        preg_match("/^{$key}=[^\r\n]*/m", $envFile, $matches);

        if (count($matches)) {
            return substr($matches[0], strlen($key) + 1);
        }

        return '';
    }
}

<?php

namespace P5ych0\Laracrypt;

use DomainException;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;

/**
 * Obfuscates integers to use with short-URL-like service
 *
 * @author ck
 */
class Shortener extends Obfuscator
{
    /**
     * Chars to use with obfuscator
     *
     * @var string Chars to use
     */
    private $chars;

    /**
     * Better if it is a simple number
     *
     * @var int Length of chars
     */
    private $len;

    /**
     * A simple number for multiplication that adds the security
     *
     * @var int Simple multiplicator
     */
    private $simple;

    /**
     * Security addition
     *
     * @var int Addition to default value
     */
    private $add;

    /**
     * Max value to encrypt
     *
     * @var int
     */
    private $max;

    /**
     * @param  string           $chars
     * @param  int              $simple
     * @param  int              $add
     * @throws \DomainException
     */
    public function __construct(string $chars, int $simple, int $add)
    {
        $this->len = mb_strlen($chars, "8bit");

        if ($this->len < 13 || $add < 2000) {
            throw new DomainException("Too weak obfuscation");
        }

        $this->chars  = $chars;
        $this->simple = $simple;
        $this->add    = $add;
        $this->max    = floor((9999998959999946 - $add) / $simple);
    }

    /**
     * Obfuscate ID
     *
     * @param  int                                               $data ID to obfuscate
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     * @return string                                            Obfuscated ID
     */
    public function encrypt($data): string
    {
        if (!is_int($data) || $data < 1) {
            throw new EncryptException("Value must be positive integer");
        }

        if ($data > $this->max) {
            throw new EncryptException(sprintf("Value must be lesser than or equal to %d", $this->max));
        }

        $num = $data * $this->simple + $this->add;
        $res = '';
        $x   = 0;

        while ($num) {
            $res .= $this->chars[$x = ($num + $x) % $this->len];
            $num = (int) ($num / $this->len);
        }

        return $res;
    }

    /**
     * Deobfuscate ID
     *
     * @param  string                                            $encrypted Obfuscated string
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     * @return int                                               Deobfuscated ID
     */
    public function decrypt(string $encrypted): int
    {
        if (!preg_match("#^[{$this->chars}]{3,10}$#", $encrypted)) {
            throw new DecryptException("Malformed input");
        }

        $res = $x = 0;
        $mul = 1;

        foreach (str_split($encrypted) as $c) {
            $res += $mul * ((strpos($this->chars, $c) + $this->len - $x) % $this->len);
            $mul *= $this->len;
            $x = strpos($this->chars, $c);
        }

        $res -= $this->add;

        if ($res <= 0 || ($res % $this->simple) !== 0) {
            throw new DecryptException("Can't deobfuscate value");
        }

        $res /= $this->simple;

        return $res;
    }
}

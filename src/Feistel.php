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

use DomainException;
use RuntimeException;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\DecryptException;

/**
 * Feistel encoder
 *
 * @author Kostiantyn Karnasevych <constantine.karnacevych@gmail.com>
 */
class Feistel extends Obfuscator
{
    /**
     * Mask (only 30 masks are allowed from 0x3 to 0x7fffffff)
     *
     * @var int
     */
    protected $mask;

    /**
     * Half shift
     *
     * @var int
     */
    protected $bits;

    /**
     * Keys used in rounds
     *
     * @var array
     */
    protected $roundKeys = [];

    /**
     * Key to encrypt with
     * Value up to 0xFFFFFFFF is enough
     *
     * @var int
     */
    protected $key;

    /**
     * Number of valid rounds
     *
     * @var int
     */
    protected $rounds;

    /**
     * Max allowed value to encrypt
     * Set with respect to mask
     *
     * @var int
     */
    protected $max;

    /**
     * Max printable characters to return (2-19)
     *
     * @var int
     */
    protected $printable;

    /**
     * Mode to make serial (TRUE - with letters)
     *
     * @var bool
     */
    private $mode = false;

    /**
     * Constructor
     *
     * @param bool $mode With/without letters
     * @param int  $mask Mask to use (impact produced length and max allowed number)
     * @param int  $key  Key to use with Feistel
     */
    public function __construct(bool $mode, int $mask, int $key)
    {
        if ($this->supported($mask, $key)) {
            $this->mask = $mask;
            $this->key  = $key;
        }

        $this->mode      = $mode;
        $this->bits      = strlen(decbin($this->mask));
        $this->max       = pow(2, $this->bits * 2) - 1;
        $this->printable = strlen((string) $this->max);

        $this->setup();
    }

    /**
     * Setup round keys
     *
     * @throws \DomainException
     */
    protected function setup(): void
    {
        $temp = $this->key;

        while ($temp > 0) {
            $this->roundKeys[] = $temp & $this->mask;
            $this->roundKeys[] = ~($temp & $this->mask);

            $temp = $temp >> $this->bits;

            if ($temp > 0) {
                $this->roundKeys[] = $temp;
                $this->roundKeys[] = ~$temp;
            }
        }

        $this->rounds = floor(count($this->roundKeys) / 4) * 4;

        if ($this->rounds < 4) {
            if (count($this->roundKeys) >= 2) {
                $this->rounds = 2;
            } else {
                throw new DomainException("Can't proceed without defined rounds");
            }
        } elseif ($this->rounds > 8) {
            $this->rounds = 8;
        }
    }

    /**
     * Get max printable characters if TRUE, otherwise MAX allowed value or power of 2 if NULL
     *
     * @param  null|bool $printable optional
     * @return int
     */
    public function getMax($printable = false): int
    {
        return $printable ? $this->printable : ($printable === null ? $this->bits * 2 : $this->max);
    }

    /**
     * Encrypt int
     *
     * @param  int                                               $data Int value to encrypt
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     * @return string                                            Encrypted value
     */
    public function encrypt($data): string
    {
        if (!is_int($data) || $data <= 0) {
            throw new EncryptException("Value must be positive integer");
        }

        if ($data > $this->max) {
            throw new EncryptException(sprintf("Value must be lesser than or equal to %d", $this->max));
        }

        $rhs = $data & $this->mask;
        $lhs = $this->shift($data, $this->bits);

        for ($i = 0; $i < $this->rounds; ++$i) {
            if ($i > 0) {
                list($rhs, $lhs) = [$lhs, $rhs];
            }

            $rhs ^= $this->feistel($lhs, $i);
            $rhs = $rhs & $this->mask;
        }

        $out = sprintf("%0" . $this->printable . "d", ($lhs << $this->bits) + ($rhs & $this->mask));

        if ($this->mode === true) {
            return chr(((int) ($out[0]) * 2) + 65) . chr((((int) ($out[1]) + 2) * 2) + 66) . chr((((int) ($out[2]) + 1) * 2) + 63) . " " . substr($out, 3);
        }

        return $out;
    }

    /**
     * Decrypt int
     *
     * @param  string                                            $encrypted Value to decrypt
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     * @return int                                               Decrypted value
     */
    public function decrypt(string $encrypted): int
    {
        $len = $this->printable - 3;

        if (!preg_match($this->mode === true ? "#^[A-Z]{3}\s*\d{{$len}}$#" : "#^\d{{$this->printable}}$#", $encrypted)) {
            throw new DecryptException("Malformed input");
        }

        $data = (int) ($this->mode === true ? ((ord($encrypted[0]) - 63) / 2 - 1) . ((ord($encrypted[1]) - 66) / 2 - 2) . ((ord($encrypted[2]) - 65) / 2) . substr($encrypted, -$len) : $encrypted);

        $rhs = $data & $this->mask;
        $lhs = $this->shift($data, $this->bits);

        for ($i = 0; $i < $this->rounds; ++$i) {
            if ($i > 0) {
                list($rhs, $lhs) = [$lhs, $rhs];
            }

            $rhs ^= $this->feistel($lhs, $this->rounds - 1 - $i);
            $rhs = $rhs & $this->mask;
        }

        return ($lhs << $this->bits) + ($rhs & $this->mask);
    }

    /**
     * @param  int               $mask
     * @param  int               $key
     * @throws \RuntimeException
     * @return bool
     */
    protected function supported(int $mask, int $key): bool
    {
        if ($mask < 3) {
            throw new RuntimeException("The mask cannot be lesser than 0x03");
        }

        if ($mask > 0x7fffffff) {
            throw new RuntimeException("The mask should not be greater than 0x7fffffff");
        }

        $test = dechex($mask);

        if (!preg_match("#^[137f]f*$#", $test)) {
            throw new RuntimeException("Bad mask 0x${test}");
        }

        if ($key < 0) {
            throw new RuntimeException("Key is invalid");
        }

        $min = ($mask + 1) / 2 - 1;

        if ($key <= $min) {
            throw new RuntimeException("Can't operate with such a short key 0x" . dechex($key) . ". Value must be greater than 0x" . dechex($min));
        }

        return true;
    }

    /**
     * Shift value
     *
     * @param  int $val
     * @param  int $n
     * @return int
     */
    protected function shift(int $val, int $n): int
    {
        return ($val >= 0 ? $val : $val + $this->mask + 1) >> $n;
    }

    /**
     * Feistel function
     *
     * @param  int $num
     * @param  int $round
     * @return int
     */
    protected function feistel(int $num, int $round): int
    {
        $num ^= $this->roundKeys[$round];
        $num *= $num;

        return $this->shift($num, $this->bits) ^ ($num & $this->mask);
    }
}

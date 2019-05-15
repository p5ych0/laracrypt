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

if (!function_exists("safeBase64")) {
    /**
     * Make Base64 encoded string safe for web usage (URL)
     *
     * @param  string $str
     * @param  bool   $in
     * @return mixed
     */
    function safeBase64(string $str, bool $in = true)
    {
        return $in ?
            strtr(base64_encode($str), ['=' => ';', '/' => '-', '+' => '_']) :
            base64_decode(strtr($str, ['-' => '/', '_' => '+', ';' => '=']), true);
    }
}

if (!function_exists("as_uuid")) {
    /**
     * Format a 32 chars string into UUID format
     *
     * @param  string                    $str
     * @throws \InvalidArgumentException
     * @return string
     */
    function as_uuid(string $str): string
    {
        if (!preg_match("#^[a-f\d]{32}#", $str)) {
            throw new InvalidArgumentException("Only hexadecimals in lower case can be accepted");
        }

        return substr($str, 0, 8) . "-" . substr($str, 8, 4) . "-" . substr($str, 12, 4)  . "-" . substr($str, 16, 4)  . "-" . substr($str, 20, 12);
    }
}

if (!function_exists("is_uuid")) {
    /**
     * Check whether match UUID format
     *
     * @param  string $str Lowercased
     * @return bool
     */
    function is_uuid(string $str): bool
    {
        return preg_match("#^[a-f\d]{8}-(?:[a-f\d]{4}-){3}[a-f\d]{12}$#", $str) > 0;
    }
}

if (!function_exists("is_prime")) {
    /**
     * Whether number is prime
     *
     * @param  int  $number
     * @return bool
     */
    function is_prime(int $number): bool
    {
        return in_array($number, [2, 3, 5], true) || ($number > 1 && $number % 2 >= 1 && $number % 3 >= 1 && $number % 5 >= 1);
    }
}

if (!function_exists("next_prime")) {
    /**
     * Find next prime number under 100000
     *
     * @param  int                        $number
     * @throws \]InvalidArgumentException
     * @throws \DomainException
     * @return int
     */
    function next_prime(int $number): int
    {
        if ($number < 0) {
            throw new InvalidArgumentException("Number must be positive");
        }

        while (is_prime($number) === false) {
            if ($number++ > 100000) {
                throw new DomainException("Only prime numbers in range of 2..100000 are allowed");
            }
        }

        return $number;
    }
}

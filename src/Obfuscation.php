<?php

namespace P5ych0\Laracrypt;

interface Obfuscation
{
    /**
     * Decrypt the encrypted string
     *
     * @param  string $encrypted
     * @return mixed
     */
    public function decrypt(string $encrypted);
}

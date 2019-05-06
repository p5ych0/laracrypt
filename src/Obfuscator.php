<?php

namespace P5ych0\Laracrypt;

abstract class Obfuscator implements Obfuscation
{
    /**
     * Encrypt the data
     *
     * @param  mixed  $data
     * @return string
     */
    abstract public function encrypt($data): string;
}

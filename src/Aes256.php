<?php

namespace P5ych0\Laracrypt;

use RuntimeException;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\DecryptException;

/**
 * AES-256 safe for web
 *
 * @author ck
 */
class Aes256 extends Obfuscator
{
    const ROUNDS = 3;

    /**
     * Key
     *
     * @var string
     */
    private $key;

    /**
     * Crypt cipher
     *
     * @var string
     */
    private $cipher;

    /**
     * @param  string            $key
     * @param  string            $cipher
     * @throws \RuntimeException
     */
    public function __construct(string $key, string $cipher)
    {
        if ($this->supported($key, $cipher)) {
            $this->key    = $key;
            $this->cipher = $cipher;
        } else {
            throw new RuntimeException('The only supported cipher is AES-256-CBC with the correct key length.');
        }
    }

    /**
     * decrypt AES 256
     *
     * @param  string $encrypted Base64 encoded data
     * @return mixed  decrypted data
     */
    public function decrypt(string $encrypted)
    {
        $data = \safeBase64($encrypted, false);
        $salt = substr($data, 0, 16);
        $ct   = substr($data, 16);
        $key  = $this->key . $salt;
        $hash = [$result = hash('sha256', $key, true)];

        for ($i = 1; $i < self::ROUNDS; ++$i) {
            $result .= $hash[$i] = hash('sha256', $hash[$i - 1] . $key, true);
        }

        $key = substr($result, 0, 32);
        $iv  = substr($result, 32, 16);

        $return = igbinary_unserialize(openssl_decrypt($ct, $this->cipher, $key, true, $iv));

        if ($return === false) {
            throw new DecryptException("Can't decrypt");
        }

        return $return;
    }

    /**
     * crypt AES 256
     *
     * @param  mixed                                             $data Data to encrypt
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     * @return string                                            base64 encrypted data
     */
    public function encrypt($data): string
    {
        if ($data === false) {
            throw new EncryptException("Can't encrypt FALSE");
        }
        // Set a random salt
        $salt   = openssl_random_pseudo_bytes(16);
        $salted = '';
        $dx     = '';
        // Salt the key(32) and iv(16) = 48
        while (strlen($salted) < 48) {
            $salted .= $dx = hash('sha256', $dx . $this->key . $salt, true);
        }

        $key = substr($salted, 0, 32);
        $iv  = substr($salted, 32, 16);

        $encryptedData = openssl_encrypt(igbinary_serialize($data), $this->cipher, $key, true, $iv);

        return \safeBase64($salt . $encryptedData);
    }

    /**
     * @param  string $key
     * @param  string $cipher
     * @return bool
     */
    protected function supported(string $key, string $cipher): bool
    {
        return mb_strlen($key, "8bit") === 32 && $cipher === "AES-256-CBC";
    }
}

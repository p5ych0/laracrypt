<?php

namespace P5ych0\Laracrypt;

use RuntimeException;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;

/**
 * UUID-pretender
 *
 * @author ck
 */
class UUID extends Obfuscator
{
    /**
     * @var string Crypto-algo (AES-256-CBC)
     */
    private $cipher;

    /**
     * @var string Password (40 chars)
     */
    private $pass;

    /**
     * @var string Initialization vector (16 chars)
     */
    private $iv;

    /**
     * Constructor (initialized as signleton for application)
     *
     * @param  string            $cipher
     * @param  string            $pass
     * @param  string            $iv
     * @throws \RuntimeException
     */
    public function __construct(string $cipher, string $pass, string $iv)
    {
        if ($this->supported($cipher, $pass, $iv)) {
            $this->cipher = $cipher;
            $this->pass   = $pass;
            $this->iv     = $iv;
        } else {
            throw new RuntimeException('The only supported cipher is AES-256-CBC with the correct pass and IV lengths.');
        }
    }

    /**
     * Encrypt integer entity ID to pretend UUID
     *
     * @param  int                                               $data  Main value (64 bit)
     * @param  int                                               $value optional Additional value (signed 32 bit)
     * @param  int                                               $owner optional Main value' owner (1-255) @see config/entities.php
     * @param  int                                               $flag  optional Flag (bitset, 00-FF)
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     * @return string                                            UUID-pretending string
     */
    public function encrypt($data, int $value = null, int $owner = 0, int $flag = 0): string
    {
        if (!is_int($data) || $data < 1) {
            throw new EncryptException("Value must be positive integer");
        }

        if ($owner < 0 || $owner > 255 || $flag < 0 || $flag > 255 || $data < 0 || ($value !== null && $value < -2147483648 || $value > 2147483647)) {
            throw new EncryptException("Can't encrypt int");
        }

        return as_uuid(unpack("H*",
            openssl_encrypt(
                pack('Jln', $data, $value ?? 0, $flag << 8 | $owner),
                $this->cipher,
                $this->pass,
                OPENSSL_RAW_DATA,
                $this->iv
            )
        )[1]);
    }

    /**
     * Decrypt UUID-like string into array (id, value, owner, flag)
     *
     * @param  string                                            $encrypted
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     * @return int[]
     */
    public function decrypt(string $encrypted): array
    {
        if (!is_uuid($encrypted)) {
            throw new DecryptException("Malformed input");
        }

        $ret = @unpack(
            'J1id/l1value/n1flag',
            openssl_decrypt(
                pack('H*', strtr($encrypted, ["-" => ""])),
                $this->cipher,
                $this->pass,
                OPENSSL_RAW_DATA,
                $this->iv
            )
        );

        if ($ret['id'] < 1) {
            throw new DecryptException("Can't decrypt int");
        }

        $flag = $ret['flag'];

        unset($ret['flag']);

        $ret['owner'] = $flag & 255;
        $ret['flag']  = $flag >> 8;

        if ($ret['owner'] < 0 || $ret['owner'] > 255) {
            throw new DecryptException("Can't decrypt int, bad owner");
        }

        if ($ret['flag'] < 0 || $ret['flag'] > 255) {
            throw new DecryptException("Can't decrypt int, bad flag");
        }

        return $ret;
    }

    /**
     * Determine if the given pass, IV and cipher combination is valid.
     *
     * @param  string $cipher
     * @param  string $pass
     * @param  string $iv
     * @return bool
     */
    protected function supported(string $cipher, string $pass, string $iv): bool
    {
        return mb_strlen($iv, "8bit") === 16 && $cipher === "AES-256-CBC" && mb_strlen($pass, "8bit") === 64;
    }
}

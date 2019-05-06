<?php

namespace P5ych0\Laracrypt;

use InvalidArgumentException;
use LogicException;
use ReflectionException;
use RuntimeException;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\DecryptException;

/**
 * SSL key based encryption
 *
 * @author ck
 * @requires pecl-igbinary
 */
class SSL extends Obfuscator
{
    /**
     * Path to key storage
     *
     * @var string
     */
    private $path;

    /**
     * Owner's identity
     *
     * @var string
     */
    private $owner;

    /**
     * Constructor
     *
     * @throws \RuntimeException
     */
    public function __construct()
    {
        $path = $this->storage() . "/keys";

        if (!file_exists($path)) {
            mkdir($path, 0750, true);
            clearstatcache(true, $path);
        }

        if (!is_dir($path)) {
            throw new RuntimeException("Directory doesn't exists");
        }

        $perms = substr(sprintf("%o", fileperms($path)), -4);

        if (!in_array($perms, ["0770", "0700", "0750"], true)) {
            throw new RuntimeException("Directory has too open permissions " . $perms);
        }

        $this->path = $path;
    }

    /**
     * Set owner
     *
     * @param  string                    $owner
     * @throws \InvalidArgumentException
     * @return self
     */
    public function setOwner(string $owner)
    {
        if (!preg_match("#^[\w-]{6,64}$#", $owner)) {
            throw new InvalidArgumentException("Valid owner can contain only alphanumeric characters, dash and underscore, the length must be between 6 and 64 characters");
        }

        $this->owner = $owner;

        return $this->validateKeyFiles();
    }

    /**
     * Generate private key
     *
     * @throws \RuntimeException
     * @throws \LogicException
     * @return self
     */
    public function generatePrivateKey()
    {
        if ($this->owner === null) {
            throw new LogicException("Owner cannot be null");
        }

        $test = system("cd " . $this->path .
            " && openssl genpkey -algorithm RSA -out " .
            $this->owner . ".prv -pkeyopt rsa_keygen_bits:4096" .
            " && chmod 0440 " . $this->owner . ".prv", $code);

        if ($test === false || $code !== 0) {
            throw new RuntimeException("Can't generate private key");
        }

        clearstatcache(true, $this->path . DIRECTORY_SEPARATOR . $this->owner . ".prv");

        return $this;
    }

    /**
     * Encrypt the data
     *
     * @param  mixed                                             $data Data to encrypt
     * @throws \RuntimeException
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     * @return string                                            Base64 encoded string
     */
    public function encrypt($data): string
    {
        $file = $this->path . DIRECTORY_SEPARATOR . $this->owner . ".prv";

        if (stream_resolve_include_path($file) === false) {
            throw new RuntimeException("Can't open private key");
        }

        $key     = openssl_pkey_get_private("file://" . $file);
        $details = openssl_pkey_get_details($key);

        if ($details === null) {
            throw new RuntimeException("Can't obtain private key details");
        }

        $size = ceil($details['bits'] / 8) - 11;

        unset($details);

        $raw = igbinary_serialize($data);
        $out = "";

        while ($raw) {
            $chunk = substr($raw, 0, $size);
            $raw   = substr($raw, $size);

            if (openssl_private_encrypt($chunk, $crypted, $key) === false) {
                throw new EncryptException("Failed to encrypt data");
            }

            $out .= $crypted;
        }

        openssl_pkey_free($key);

        return base64_encode($out);
    }

    /**
     * Decrypt data
     *
     * @param  string                                            $encrypted base64 encoded string
     * @throws \RuntimeException
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     * @return mixed
     */
    public function decrypt(string $encrypted)
    {
        $file = $this->path . "/" . $this->owner . ".pub";

        if (stream_resolve_include_path($file) === false) {
            throw new RuntimeException("Can't open public key");
        }

        $key     = openssl_pkey_get_public("file://" . $file);
        $details = openssl_pkey_get_details($key);

        if ($details === null) {
            throw new RuntimeException("Can't obtain public key details");
        }

        $size = ceil($details["bits"] / 8);

        unset($details);

        $data = base64_decode($encrypted, true);

        if (empty($data)) {
            throw new DecryptException("Cannot be processed");
        }

        $out  = "";

        while ($data) {
            $chunk = substr($data, 0, $size);
            $data  = substr($data, $size);

            if (openssl_public_decrypt($chunk, $decrypted, $key) === false) {
                throw new DecryptException("Failed to decrypt data");
            }

            $out .= $decrypted;
        }

        openssl_pkey_free($key);

        return igbinary_unserialize($out);
    }

    /**
     * Extract and write public key from private
     *
     * @throws \RuntimeException
     * @return self
     */
    private function generatePublicKey()
    {
        $file = $this->path . DIRECTORY_SEPARATOR . $this->owner;

        $key     = openssl_pkey_get_private("file://" . $file . ".prv");
        $details = openssl_pkey_get_details($key);

        if ($details === null || empty($details["key"])) {
            throw new RuntimeException("Can't load public key");
        }

        file_put_contents($file . ".pub", $details["key"]);
        unset($details);
        chmod($file . ".pub", 0440);

        openssl_pkey_free($key);

        clearstatcache(true, $file . ".pub");

        return $this;
    }

    /**
     * Check private file for correct permissions
     *
     * @throws \RuntimeException
     * @return self
     */
    private function validateKeyFiles()
    {
        $file = $this->path . DIRECTORY_SEPARATOR . $this->owner . ".";

        stream_resolve_include_path($file . "prv") or $this->generatePrivateKey();

        $kperms = substr(sprintf("%o", fileperms($file . "prv")), -4);

        if (!in_array($kperms, ["0640", "0600", "0660", "0440", "0400"], true)) {
            throw new RuntimeException("Private key file has too open permissions " . $kperms);
        }

        stream_resolve_include_path($file . "pub") or $this->generatePublicKey();

        $perms = substr(sprintf("%o", fileperms($file . "pub")), -4);

        if (!in_array($perms, ["0640", "0600", "0660", "0440", "0400"], true)) {
            throw new RuntimeException("Public key file has too open permissions " . $perms);
        }

        return $this;
    }

    private function storage()
    {
        try {
            $path = storage_path();
        } catch (ReflectionException $e) {
            $path = "/tmp";
        }

        return $path;
    }
}

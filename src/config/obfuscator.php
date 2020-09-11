<?php

return [
    "cipher" => "AES-256-CBC",

    "key"    => env("APP_KEY", "base64:+wAzEKI0D5eOsSwqtnIPTQs8uRirBzo1AbpdZ6QczX8="),
    "pass"   => env("OBFUSCATOR_PASS", hash("sha256", "My Secret Pass")),
    "iv"     => env("OBFUSCATOR_IV", substr(hash("sha256", "Secret vector (IV)"), 0, 16)),

    "chars"  => env("OBFUSCATOR_CHARS", "CB1Aqayku37HspzE8olFgmxvjhdDw04962frcnbet5i"), // minimum 13 chars
    "simple" => env("OBFUSCATOR_SIMPLE", 47), // simple number > 47
    "add"    => env("OBFUSCATOR_ADD", 2341), // > 2000, if simple it is better

    "fkey"   => env("FEISTEL_KEY", 0xDC1FA093), // encoding key
    "fmode"  => env("FEISTEL_MODE", true), // serie like ADA prepends 8 digits
    "fmask"  => env("FEISTEL_MASK", 0x3FFFF), // 11 chars (max 68 719 476 735) 2^36

    "ssl"    => env("SSL_ENCRYPTION", false),
];

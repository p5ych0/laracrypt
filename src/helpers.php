<?php

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

<?php

declare(strict_types=1);

namespace Sentinel\Auth;

/**
 * Time-based one-time passwords (RFC 6238: HMAC-SHA1, 6 digits, 30-second steps).
 * Compatible with common authenticator apps.
 *
 * Security assumptions:
 * - Secrets are 160 random bits (the RFC 4226 recommendation).
 * - Codes are accepted for the current step plus or minus one, to allow for clock drift.
 * - Replay protection: a code is only accepted if its step is newer than the
 *   last step used by that user. The caller stores the returned step.
 * - Codes are compared in constant time.
 */
final class Totp
{
    public const PERIOD = 30;
    public const DIGITS = 6;
    private const WINDOW = 1;
    private const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** A new random Base32 secret (32 characters = 160 bits). */
    public static function generateSecret(): string
    {
        return self::base32Encode(random_bytes(20));
    }

    /** The code for a secret at a time step. */
    public static function code(string $base32Secret, int $step): string
    {
        $key = self::base32Decode($base32Secret);
        $counter = pack('J', $step); // 64-bit big-endian
        $hash = hash_hmac('sha1', $counter, $key, true);
        $offset = ord($hash[19]) & 0x0f;
        $value = ((ord($hash[$offset]) & 0x7f) << 24)
            | (ord($hash[$offset + 1]) << 16)
            | (ord($hash[$offset + 2]) << 8)
            | ord($hash[$offset + 3]);
        return str_pad((string) ($value % (10 ** self::DIGITS)), self::DIGITS, '0', STR_PAD_LEFT);
    }

    /** The 30-second time step for a Unix time (default: now). */
    public static function currentStep(?int $now = null): int
    {
        return intdiv($now ?? time(), self::PERIOD);
    }

    /**
     * Check a code.
     *
     * @param string   $base32Secret The user's secret (decrypted).
     * @param string   $code         Untrusted user input. Spaces are ignored.
     * @param int|null $lastStep     Last step this user already used (replay protection).
     * @return int|null The matched step (store it as the new last step), or null if the code is invalid.
     */
    public static function verify(string $base32Secret, string $code, ?int $lastStep, ?int $now = null): ?int
    {
        $code = preg_replace('/\s+/', '', $code) ?? '';
        if (!preg_match('/^[0-9]{' . self::DIGITS . '}$/', $code)) {
            return null;
        }
        $current = self::currentStep($now);
        $matched = null;
        // Check every step in the window without stopping early, so timing doesn't reveal which step matched.
        for ($step = $current - self::WINDOW; $step <= $current + self::WINDOW; $step++) {
            if (hash_equals(self::code($base32Secret, $step), $code) && ($lastStep === null || $step > $lastStep)) {
                $matched ??= $step;
            }
        }
        return $matched;
    }

    /**
     * The otpauth:// URI that authenticator apps read from the QR code.
     *
     * @param string $issuer  Product name shown in the app (white-label aware).
     * @param string $account Username.
     */
    public static function provisioningUri(string $issuer, string $account, string $base32Secret): string
    {
        return 'otpauth://totp/' . rawurlencode($issuer . ':' . $account)
            . '?secret=' . $base32Secret
            . '&issuer=' . rawurlencode($issuer)
            . '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::PERIOD;
    }

    /** RFC 4648 Base32 without padding (the format authenticator apps expect). */
    public static function base32Encode(string $bytes): string
    {
        $bits = '';
        foreach (str_split($bytes) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::BASE32[bindec(str_pad($chunk, 5, '0'))];
        }
        return $out;
    }

    /**
     * @throws \InvalidArgumentException on characters outside the Base32 alphabet.
     */
    public static function base32Decode(string $base32): string
    {
        $base32 = strtoupper(rtrim($base32, '='));
        $bits = '';
        foreach (str_split($base32) as $char) {
            $pos = strpos(self::BASE32, $char);
            if ($pos === false) {
                throw new \InvalidArgumentException('Invalid Base32 secret.');
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr(bindec($byte));
            }
        }
        return $out;
    }
}

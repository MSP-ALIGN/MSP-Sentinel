<?php

declare(strict_types=1);

namespace Sentinel\Core;

/**
 * Encrypts secrets at rest (TOTP seeds now, and later SMTP passwords,
 * webhook URLs and API keys) with libsodium's secretbox (XSalsa20-Poly1305).
 *
 * Format: "v1:" + base64(nonce || ciphertext). The version prefix allows
 * changing the algorithm or the key later.
 *
 * Security assumptions:
 * - Separate subkeys are derived from the app key for encryption and for
 *   HMAC (libsodium KDF), so the one key is never used for two jobs.
 * - The key is in the config file, NOT in the database. A database dump on
 *   its own doesn't reveal the secrets.
 * - Each message gets a fresh random nonce.
 * - Decryption fails closed: tampered or foreign data throws, never returns
 *   partial plaintext.
 */
final class Crypto
{
    private readonly string $encKey;
    private readonly string $macKey;

    /** @param string $appKey 32-byte master key from the config file. */
    public function __construct(string $appKey)
    {
        if (strlen($appKey) !== SODIUM_CRYPTO_KDF_KEYBYTES) {
            throw new \InvalidArgumentException('Encryption key must be 32 bytes.');
        }
        $this->encKey = sodium_crypto_kdf_derive_from_key(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 1, 'SentEnc1', $appKey);
        $this->macKey = sodium_crypto_kdf_derive_from_key(32, 2, 'SentMac1', $appKey);
    }

    /** Encrypt a secret for storage. Returns the "v1:" text format. */
    public function encrypt(string $plaintext): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return 'v1:' . base64_encode($nonce . sodium_crypto_secretbox($plaintext, $nonce, $this->encKey));
    }

    /**
     * @param string $encoded Value from the database (trusted source, but could be corrupted).
     * @throws \RuntimeException if the value is malformed, tampered with or encrypted with another key.
     */
    public function decrypt(string $encoded): string
    {
        if (!str_starts_with($encoded, 'v1:')) {
            throw new \RuntimeException('Unknown encrypted value format.');
        }
        $raw = base64_decode(substr($encoded, 3), true);
        if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            throw new \RuntimeException('Encrypted value is corrupted.');
        }
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $nonce, $this->encKey);
        if ($plain === false) {
            throw new \RuntimeException('Encrypted value could not be decrypted (wrong key or tampered).');
        }
        return $plain;
    }

    /**
     * Keyed hash for values we only need to compare, never read back
     * (e.g. recovery codes). It's fast but useless without the app key.
     */
    public function hmac(string $value): string
    {
        return hash_hmac('sha256', $value, $this->macKey);
    }
}

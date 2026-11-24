<?php

declare(strict_types=1);

namespace Sentinel\Core;

/**
 * Encrypts secrets at rest (TOTP seeds now, and later SMTP passwords,
 * webhook URLs and API keys) with libsodium's secretbox (XSalsa20-Poly1305).
 *
 * Formats:
 * - "v2:" + base64(nonce || ciphertext) (1.34): XChaCha20-Poly1305 with associated data naming what the value is
 *   ("setting:smtp_password", "totp:7"), so a value copied to another setting or another user's row, or an older
 *   value of a different setting put back, fails to decrypt (it is bound to its place). Used for everything new.
 * - "v1:" + base64(nonce || ciphertext): secretbox without a binding, from before 1.34. Read only where a caller
 *   allows it (the 1.34 migration, which rewrites every stored value as v2).
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
    private readonly string $aeadKey;

    /** @param string $appKey 32-byte master key from the config file. */
    public function __construct(string $appKey)
    {
        if (strlen($appKey) !== SODIUM_CRYPTO_KDF_KEYBYTES) {
            throw new \InvalidArgumentException('Encryption key must be 32 bytes.');
        }
        $this->encKey = sodium_crypto_kdf_derive_from_key(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 1, 'SentEnc1', $appKey);
        $this->macKey = sodium_crypto_kdf_derive_from_key(32, 2, 'SentMac1', $appKey);
        $this->aeadKey = sodium_crypto_kdf_derive_from_key(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, 3, 'SentEnc2', $appKey);
    }

    /**
     * Encrypt a secret bound to its place ($context, e.g. "setting:smtp_password"). Returns the "v2:" text format.
     */
    public function encryptFor(string $context, string $plaintext): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        return 'v2:' . base64_encode($nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $context, $nonce, $this->aeadKey));
    }

    /**
     * Decrypt a value stored with encryptFor() for the same $context. A "v1:" value (no binding) is accepted only
     * when $allowLegacy is true (the migration that upgrades stored values).
     *
     * @throws \RuntimeException if the value is malformed, tampered with, bound elsewhere or encrypted with another key.
     */
    public function decryptFor(string $context, string $encoded, bool $allowLegacy = false): string
    {
        if (str_starts_with($encoded, 'v1:') && $allowLegacy) {
            return $this->decrypt($encoded);
        }
        if (!str_starts_with($encoded, 'v2:')) {
            throw new \RuntimeException('Unknown encrypted value format.');
        }
        $raw = base64_decode(substr($encoded, 3), true);
        $n = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
        if ($raw === false || strlen($raw) < $n + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
            throw new \RuntimeException('Encrypted value is corrupted.');
        }
        $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(substr($raw, $n), $context, substr($raw, 0, $n), $this->aeadKey);
        if ($plain === false) {
            throw new \RuntimeException('Encrypted value could not be decrypted (wrong key, tampered, or not stored for this place).');
        }
        return $plain;
    }

    /** Encrypt in the old "v1:" format (no binding). Kept for tests and old data; new code uses encryptFor(). */
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

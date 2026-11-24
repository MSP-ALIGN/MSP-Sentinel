<?php

declare(strict_types=1);

namespace Sentinel\AgentClient;

/**
 * The agent's own key pair (P-256), for secrets sent to it through Sentinel: a site's directory password is
 * encrypted in the admin's browser to this agent's public key (ECDH with a one-off browser key, HKDF-SHA256,
 * AES-256-GCM; public/assets/js/agent-seal.js), so Sentinel only ever relays a box it can't open.
 *
 * The private key is created on first use and kept in the agent's own directory (0600, the agent's user only). It
 * never leaves the appliance; only the public half is sent to Sentinel at check-in. A sealed box stays sealed on disk
 * too (Credentials keeps the box, not the password): the password exists only in memory, while a check uses it.
 *
 * Untrusted: every sealed box (it arrives through Sentinel). open() returns null for anything that isn't a box for
 * this key with exactly the expected binding (AAD): a box made for another agent, another user name or another drop
 * can't be replayed here.
 */
final class AgentKey
{
    /** HKDF "info": ties keys derived here to this one use. Must match agent-seal.js. */
    public const INFO = 'msp-sentinel-sealed-v1';
    private const MAX_SEALED = 8192;

    private \OpenSSLAsymmetricKey $private;

    /** @param string $file Private key file (created 0600 when missing). */
    public function __construct(private readonly string $file)
    {
        if (is_file($file)) {
            $key = openssl_pkey_get_private((string) file_get_contents($file));
            if ($key === false) {
                throw new \RuntimeException('The agent key file is unreadable: ' . $file);
            }
            $this->private = $key;
            return;
        }
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        if ($key === false || !openssl_pkey_export($key, $pem)) {
            throw new \RuntimeException('Could not create the agent key.');
        }
        $old = umask(0077);
        $written = file_put_contents($file . '.tmp', $pem);
        umask($old);
        // A full disk must never leave an empty key in place (the agent would be unable to start next time).
        if ($written !== strlen($pem) || !chmod($file . '.tmp', 0600) || !rename($file . '.tmp', $file)) {
            @unlink($file . '.tmp');
            throw new \RuntimeException('Could not save the agent key: ' . $file);
        }
        $this->private = $key;
    }

    /** The public key as base64 SPKI (DER), the form browsers import. */
    public function publicKey(): string
    {
        $pem = (string) (openssl_pkey_get_details($this->private)['key'] ?? '');
        return (string) preg_replace('/-----[^-]+-----|\s+/', '', $pem);
    }

    /** A short fingerprint of a public key (SPKI base64): the first 16 bytes of its SHA-256, grouped, for comparing by eye. */
    public static function fingerprint(string $publicKey): string
    {
        $der = base64_decode($publicKey, true);
        return $der === false || $der === '' ? '' : implode(':', str_split(strtoupper(substr(hash('sha256', $der), 0, 32)), 4));
    }

    /** The binding (AAD) of a directory password box. Must match what the browser used (agent-seal.js callers). */
    public static function directoryAad(int $agentId, string $nonce, string $username): string
    {
        return 'msp-sentinel-directory-password-v1|agent=' . $agentId . '|nonce=' . $nonce . '|user=' . $username;
    }

    /**
     * Open a sealed box ({"v":1,"epk","iv","ct"} as JSON). Returns the plaintext, or null when it isn't a valid box for
     * this key and binding.
     */
    public function open(string $sealed, string $aad): ?string
    {
        if (strlen($sealed) > self::MAX_SEALED) {
            return null;
        }
        $box = json_decode($sealed, true);
        if (!is_array($box) || ($box['v'] ?? null) !== 1 || !is_string($box['epk'] ?? null) || !is_string($box['iv'] ?? null) || !is_string($box['ct'] ?? null)) {
            return null;
        }
        $epk = base64_decode($box['epk'], true);
        $iv = base64_decode($box['iv'], true);
        $ct = base64_decode($box['ct'], true);
        if ($epk === false || $iv === false || $ct === false || strlen($iv) !== 12 || strlen($ct) < 17 || strlen($epk) > 200) {
            return null;
        }
        $peer = openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($epk), 64, "\n") . "-----END PUBLIC KEY-----\n");
        if ($peer === false || (openssl_pkey_get_details($peer)['ec']['curve_name'] ?? '') !== 'prime256v1') {
            return null;
        }
        $shared = openssl_pkey_derive($peer, $this->private, 32);
        if ($shared === false) {
            return null;
        }
        // The browser's one-off public key is the HKDF salt: each box gets its own key.
        $key = hash_hkdf('sha256', $shared, 32, self::INFO, $epk);
        $plain = openssl_decrypt(substr($ct, 0, -16), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, substr($ct, -16), $aad);
        return $plain === false ? null : $plain;
    }
}

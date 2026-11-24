<?php

declare(strict_types=1);

namespace Sentinel\Agent;

/**
 * Ed25519 signatures for agent authorisations and jobs.
 *
 * The signing key is derived from the app key in the config file (never
 * stored in the database), so someone who can change the database but not
 * the config file can't approve new internal ranges or forge a job. Agents
 * pin the public key when they enrol and refuse anything not signed with it.
 *
 * Messages are canonical JSON (keys sorted at every level, no escaping of
 * slashes or Unicode), so the same data always gives the same bytes.
 *
 * Verification has no other dependencies, so the agent program uses this
 * class as well (with only the public key).
 */
final class Signer
{
    /** @param string|null $secretKey 64-byte Ed25519 secret key (server only); null for verify-only use. */
    public function __construct(private readonly ?string $secretKey)
    {
    }

    /** The server's signer, from the 32-byte app key. */
    public static function fromAppKey(string $appKey): self
    {
        $seed = hash_hmac('sha256', 'sentinel-agent-signing-v1', $appKey, true);
        return new self(sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed)));
    }

    /** Public key (base64), which agents pin. */
    public function publicKey(): string
    {
        if ($this->secretKey === null) {
            throw new \LogicException('No signing key.');
        }
        return base64_encode(sodium_crypto_sign_publickey_from_secretkey($this->secretKey));
    }

    /**
     * Sign data.
     *
     * @param array<string,mixed> $data
     * @return array{payload:string, signature:string} canonical JSON and base64 signature.
     */
    public function sign(array $data): array
    {
        if ($this->secretKey === null) {
            throw new \LogicException('No signing key.');
        }
        $payload = self::canonical($data);
        return ['payload' => $payload, 'signature' => base64_encode(sodium_crypto_sign_detached($payload, $this->secretKey))];
    }

    /** True if $signature (base64) is a valid signature of $payload by the key $publicKey (base64). */
    public static function verify(string $payload, string $signature, string $publicKey): bool
    {
        $sig = base64_decode($signature, true);
        $pk = base64_decode($publicKey, true);
        if ($sig === false || $pk === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES || strlen($pk) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return false;
        }
        return sodium_crypto_sign_verify_detached($sig, $payload, $pk);
    }

    /**
     * Canonical JSON: keys sorted at every level.
     *
     * @param array<mixed> $data
     */
    public static function canonical(array $data): string
    {
        $sort = static function (mixed $v) use (&$sort): mixed {
            if (!is_array($v)) {
                return $v;
            }
            if (!array_is_list($v)) {
                ksort($v, SORT_STRING);
            }
            return array_map($sort, $v);
        };
        return json_encode($sort($data), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }
}

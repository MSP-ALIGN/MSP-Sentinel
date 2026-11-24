<?php

declare(strict_types=1);

namespace Sentinel\System;

use Sentinel\Agent\Signer;

/**
 * The update helper's decision on a release key offered by Sentinel (Linux root helper and Windows SYSTEM task share
 * it): whether to pin the offered key, and why not.
 *
 * Rules:
 * - the offer is signed with the server key pinned in the helper's own config (root/SYSTEM-protected), names this
 *   agent, is recent (2 hours) and carries a valid Ed25519 public key;
 * - a damaged or unprotected pin ('bad') is never treated as "nothing pinned": nothing is pinned then;
 * - with nothing pinned ('absent'), the key is pinned (trust on first use: see docs/agent.md);
 * - with a key pinned, only a chain of rotation statements from it is accepted: each names the next key and is signed
 *   by the key before it (the pinned key signs the first), at most ReleaseManifest::MAX_ROTATIONS, ending at the
 *   offered key.
 *
 * Untrusted: the offer and its rotations (they come from Sentinel through the agent's folder). Trusted: $cfg and the
 * pinned key, which the caller read from protected files.
 */
final class ReleaseKeyOffer
{
    /**
     * @param array<string,mixed> $cfg    the agent config (server_public_key, agent_id)
     * @param 'ok'|'absent'|'bad' $pinState
     * @return array{ok:bool, pin:?string, message:string} pin: the key to write (null: write nothing)
     */
    public static function decide(string $offerJson, array $cfg, string $pinState, string $pinned, string $fixHint): array
    {
        $offer = json_decode($offerJson, true);
        $d = is_array($offer) && is_string($offer['payload'] ?? null) && is_string($offer['signature'] ?? null)
            && Signer::verify($offer['payload'], $offer['signature'], (string) ($cfg['server_public_key'] ?? '')) ? json_decode($offer['payload'], true) : null;
        $issued = is_array($d) ? strtotime((string) ($d['issued_at'] ?? '')) : false;
        if (!is_array($d) || ($d['type'] ?? null) !== 'agent_release_key' || ($d['agent_id'] ?? null) !== ($cfg['agent_id'] ?? false)
            || !is_string($d['key'] ?? null) || !ReleaseManifest::validPublicKey($d['key']) || $issued === false || abs(time() - $issued) > 7200) {
            return ['ok' => false, 'pin' => null, 'message' => 'The release key offer is not signed by this agent\'s Sentinel (or too old).'];
        }
        if ($pinState === 'bad') {
            return ['ok' => false, 'pin' => null, 'message' => 'The pinned release key is damaged or not protected: nothing is pinned until it is fixed by hand (' . $fixHint . ').'];
        }
        if ($pinned === $d['key']) {
            return ['ok' => true, 'pin' => null, 'message' => 'Already pinned.'];
        }
        if ($pinned !== '') {
            $current = $pinned;
            $chain = is_array($d['rotations'] ?? null) ? array_values($d['rotations']) : [];
            foreach (array_slice($chain, 0, ReleaseManifest::MAX_ROTATIONS) as $link) {
                $st = is_array($link) && is_string($link['statement'] ?? null) ? json_decode($link['statement'], true) : null;
                $sig = is_array($link) && is_string($link['signature'] ?? null) ? base64_decode($link['signature'], true) : false;
                if (!is_array($st) || ($st['type'] ?? null) !== 'release_key_rotation' || ($st['old_key'] ?? null) !== $current || !is_string($st['new_key'] ?? null)
                    || !ReleaseManifest::validPublicKey($st['new_key']) || $sig === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES
                    || !sodium_crypto_sign_verify_detached($sig, (string) $link['statement'], (string) base64_decode($current))) {
                    break;
                }
                $current = $st['new_key'];
            }
            if ($current !== $d['key']) {
                return ['ok' => false, 'pin' => null, 'message' => 'A different release key is pinned and the change is not signed by it: give the new key by hand (' . $fixHint . ').'];
            }
        }
        return ['ok' => true, 'pin' => $d['key'], 'message' => ($pinned === '' ? 'Release key pinned: ' : 'Release key rotated: ') . ReleaseManifest::keyFingerprint($d['key']) . '.'];
    }
}

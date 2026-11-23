<?php

declare(strict_types=1);

namespace Sentinel\System;

/**
 * The signed list of an agent release's files: {"v":1, "type":"msp-sentinel-agent-release", "version":"x.y.z",
 * "files":{"path":"sha256", ...}} (canonical JSON), signed with the maintainer's release key (Ed25519; only the
 * maintainer holds the secret half: bin/release-sign.php). The files are what the agent installer copies: the release
 * tree without config/, storage/, dist/, tests/ and release/ (where the manifest and its signature live).
 *
 * Who uses it: bin/release-sign.php (writes it), Sentinel (serves it and the files to agents), the agent (checks it
 * before staging an update) and the agent's root update helper (checks everything again before installing).
 *
 * Trust: only the signature with the PINNED release public key counts (/etc/sentinel-agent/release-key.pub on agents,
 * copied there by the installer; never from the code being installed). Sentinel's own keys can't vouch for code.
 *
 * Untrusted: the manifest and every file (they arrive over the network); paths are checked against a strict pattern
 * (no "..", no absolute paths, no hidden top-level files), sizes and counts are capped.
 */
final class ReleaseManifest
{
    public const TYPE = 'msp-sentinel-agent-release';
    /** Top-level folders the agent installer doesn't copy (and the manifest's own folder). */
    public const EXCLUDED = ['config/', 'storage/', 'dist/', 'tests/', 'release/'];
    public const MAX_FILES = 5000;
    public const MAX_FILE_BYTES = 8388608; // one file per request, base64 in JSON, under the agent's 16 MB answer cap

    /** Whether a manifest path is acceptable (relative, plain characters, no "..", not excluded). */
    public static function validPath(string $path): bool
    {
        if (preg_match('#^[A-Za-z0-9_][A-Za-z0-9_.\-]*(/[A-Za-z0-9_][A-Za-z0-9_.\-]*)*$#', $path) !== 1 || str_contains($path, '..') || strlen($path) > 300) {
            return false;
        }
        foreach (self::EXCLUDED as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return false;
            }
        }
        return true;
    }

    /**
     * The manifest of a release tree, from a list of its files (e.g. `git ls-files`), with their SHA-256.
     *
     * @param list<string> $paths
     * @return array{v:int, type:string, version:string, files:array<string,string>}
     */
    public static function build(string $root, string $version, array $paths): array
    {
        $files = [];
        foreach ($paths as $p) {
            if (!self::validPath($p)) {
                continue; // excluded folders, odd names
            }
            $full = $root . '/' . $p;
            if (!is_file($full) || is_link($full)) {
                continue;
            }
            $files[$p] = hash_file('sha256', $full);
        }
        ksort($files, SORT_STRING);
        if ($files === [] || count($files) > self::MAX_FILES) {
            throw new \RuntimeException('Unexpected number of release files: ' . count($files));
        }
        return ['v' => 1, 'type' => self::TYPE, 'version' => $version, 'files' => $files];
    }

    /**
     * The release files of an installed tree (for signing in the web UI, where there may be no git): every plain file
     * except excluded folders, hidden files and folders, symlinks and the install's own BUILD stamp. Sorted.
     *
     * @return list<string>
     */
    public static function listTree(string $root): array
    {
        $out = [];
        $it = new \RecursiveIteratorIterator(new \RecursiveCallbackFilterIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
            static function (\SplFileInfo $f, string $key, \RecursiveDirectoryIterator $it) use ($root): bool {
                $rel = substr($f->getPathname(), strlen($root) + 1);
                if ($f->isLink() || str_starts_with($f->getFilename(), '.')) {
                    return false;
                }
                return !$f->isDir() || self::validPath($rel . '/x');
            }
        ));
        foreach ($it as $f) {
            $rel = substr($f->getPathname(), strlen($root) + 1);
            if ($f->isFile() && $rel !== 'BUILD' && self::validPath($rel)) {
                $out[] = $rel;
                if (count($out) > self::MAX_FILES) {
                    break;
                }
            }
        }
        sort($out, SORT_STRING);
        return $out;
    }

    /** A public key's short fingerprint (for comparing by eye and in the database). */
    public static function keyFingerprint(string $publicKeyB64): string
    {
        $raw = base64_decode(trim($publicKeyB64), true);
        return $raw === false || $raw === '' ? '' : implode(':', str_split(strtoupper(substr(hash('sha256', $raw), 0, 32)), 4));
    }

    /** Whether a string is a base64 Ed25519 public key. */
    public static function validPublicKey(string $publicKeyB64): bool
    {
        $raw = base64_decode(trim($publicKeyB64), true);
        return $raw !== false && strlen($raw) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES;
    }

    /** The exact bytes that are signed. @param array<string,mixed> $manifest */
    public static function canonical(array $manifest): string
    {
        return (string) json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /** Sign (maintainer only): base64 Ed25519 signature of the canonical manifest. */
    public static function sign(string $canonical, string $secretKeyB64): string
    {
        $sk = base64_decode($secretKeyB64, true);
        if ($sk === false || strlen($sk) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \InvalidArgumentException('Not a release secret key.');
        }
        return base64_encode(sodium_crypto_sign_detached($canonical, $sk));
    }

    /**
     * Check a manifest: signed by the pinned release key, the right type, a version, and only acceptable paths with
     * SHA-256 values. Returns the manifest, or why it was refused.
     *
     * @return array{v:int, type:string, version:string, files:array<string,string>}|string
     */
    public static function verify(string $json, string $signatureB64, string $publicKeyB64): array|string
    {
        $pk = base64_decode(trim($publicKeyB64), true);
        $sig = base64_decode(trim($signatureB64), true);
        if ($pk === false || strlen($pk) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return 'no valid release public key';
        }
        if ($sig === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES || !sodium_crypto_sign_verify_detached($sig, $json, $pk)) {
            return 'not signed with the release key';
        }
        $m = json_decode($json, true);
        if (!is_array($m) || ($m['v'] ?? null) !== 1 || ($m['type'] ?? null) !== self::TYPE || !is_string($m['version'] ?? null)
            || preg_match('/^\d{1,4}\.\d{1,4}\.\d{1,4}$/', $m['version']) !== 1 || !is_array($m['files'] ?? null) || $m['files'] === [] || count($m['files']) > self::MAX_FILES) {
            return 'not an agent release manifest';
        }
        foreach ($m['files'] as $path => $hash) {
            if (!is_string($path) || !self::validPath($path) || !is_string($hash) || preg_match('/^[0-9a-f]{64}$/', $hash) !== 1) {
                return 'the manifest lists an unacceptable file';
            }
        }
        foreach (['bin/sentinel-agent.php', 'VERSION', 'install/agent-install.sh'] as $needed) {
            if (!isset($m['files'][$needed])) {
                return 'the manifest misses ' . $needed;
            }
        }
        return $m;
    }

    /** Whether version $a is newer than $b (x.y.z). */
    public static function newer(string $a, string $b): bool
    {
        return preg_match('/^\d+\.\d+\.\d+$/', $a) === 1 && (preg_match('/^\d+\.\d+\.\d+$/', $b) !== 1 || version_compare($a, $b, '>'));
    }
}

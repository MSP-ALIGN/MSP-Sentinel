<?php

declare(strict_types=1);

namespace Sentinel\Agent;

use Sentinel\System\ReleaseManifest;

/**
 * Sentinel's side of agent updates: whether this installation holds a SIGNED agent release, and serving its manifest
 * and files to agents. Sentinel only relays: agents (and their root update helper) accept the release only when it is
 * signed with the maintainer's release key they pinned at install. Sentinel never signs anything here.
 *
 * Where the release comes from: this installation's own files (the release tree it runs). The signature is made
 * either on the System page (in the admin's browser, with the key file only they hold; kept in storage/agent-release)
 * or with bin/release-sign.php (release/agent-manifest.*). The key is the one created on the System page (a setting:
 * only the public half), else install/release-key.pub. A release is offered only when the signature checks with that
 * key and its version is this installation's version.
 *
 * TEST SUITE ONLY: testing.release_root points at a separate release tree (its version may differ from Sentinel's).
 *
 * Untrusted: an agent's requested version and path (only manifest paths are served, read from inside the root).
 */
final class AgentRelease
{
    /** @var array{v:int, type:string, version:string, files:array<string,string>}|null */
    private ?array $manifest = null;
    private string $json = '';
    private string $signature = '';
    private string $why = '';

    private string $key = '';

    /**
     * @param string $uiKey  the release public key created on the System page ('' when none: install/release-key.pub)
     * @param string $uiDir  where releases signed on the System page are kept (storage/agent-release)
     */
    public function __construct(private readonly string $root, private readonly string $appVersion, private readonly bool $anyVersion = false,
        string $uiKey = '', private readonly string $uiDir = '')
    {
        $this->key = trim($uiKey) !== '' ? trim($uiKey) : trim((string) @file_get_contents($root . '/install/release-key.pub'));
        if ($this->key === '') {
            $this->why = 'no release key yet (create one on Administration, System)';
            return;
        }
        // A release signed on the System page first, then one signed with bin/release-sign.php.
        $this->why = 'this version is not signed yet (sign it on Administration, System)';
        foreach (array_filter([$uiDir, $root . '/release']) as $dir) {
            $json = (string) @file_get_contents($dir . '/agent-manifest.json');
            $sig = trim((string) @file_get_contents($dir . '/agent-manifest.sig'));
            if ($json === '') {
                continue;
            }
            $m = ReleaseManifest::verify($json, $sig, $this->key);
            if (is_string($m)) {
                $this->why = $m;
                continue;
            }
            if (!$anyVersion && $m['version'] !== $appVersion) {
                $this->why = 'the signed release is ' . $m['version'] . ', not this installation\'s ' . $appVersion;
                continue;
            }
            [$this->manifest, $this->json, $this->signature, $this->why] = [$m, $json, $sig, ''];
            return;
        }
    }

    /** The release public key in use ('' when none). */
    public function publicKey(): string
    {
        return $this->key;
    }

    /**
     * The manifest of this installation's own files, to be signed on the System page (canonical JSON), or null when
     * the files can't be listed. The version is the installation's VERSION file.
     */
    public function manifestToSign(): ?string
    {
        $version = trim((string) @file_get_contents($this->root . '/VERSION'));
        if (preg_match('/^\d+\.\d+\.\d+$/', $version) !== 1) {
            return null;
        }
        try {
            return ReleaseManifest::canonical(ReleaseManifest::build($this->root, $version, ReleaseManifest::listTree($this->root)));
        } catch (\RuntimeException) {
            return null;
        }
    }

    /**
     * Keep a signature made in the admin's browser for $manifestJson, after checking it: the manifest must be exactly
     * what this installation would sign now, and the signature valid with the release key. Returns '' or why not.
     */
    public function acceptSignature(string $manifestJson, string $signature): string
    {
        if ($this->key === '' || $this->uiDir === '') {
            return 'No release key yet.';
        }
        $now = $this->manifestToSign();
        if ($now === null || !hash_equals($now, $manifestJson)) {
            return 'The files changed since the page was opened; reload and sign again.';
        }
        if (is_string(ReleaseManifest::verify($manifestJson, $signature, $this->key))) {
            return 'That signature is not valid for the release key (wrong key file?).';
        }
        if (!is_dir($this->uiDir) && !mkdir($this->uiDir, 0750, true)) {
            return 'Could not save the signature.';
        }
        $ok = file_put_contents($this->uiDir . '/agent-manifest.json.tmp', $manifestJson) !== false && file_put_contents($this->uiDir . '/agent-manifest.sig.tmp', $signature) !== false
            && rename($this->uiDir . '/agent-manifest.sig.tmp', $this->uiDir . '/agent-manifest.sig') && rename($this->uiDir . '/agent-manifest.json.tmp', $this->uiDir . '/agent-manifest.json');
        return $ok ? '' : 'Could not save the signature.';
    }

    /** The signed agent version on offer, or null. */
    public function version(): ?string
    {
        return $this->manifest['version'] ?? null;
    }

    /** Why nothing is on offer ('' when a release is). */
    public function why(): string
    {
        return $this->why;
    }

    /** The manifest and its signature, exactly as signed. @return array{manifest:string, signature:string}|null */
    public function manifestFor(string $version): ?array
    {
        return $this->manifest !== null && $version === $this->manifest['version'] ? ['manifest' => $this->json, 'signature' => $this->signature] : null;
    }

    /** One file of the release (only paths in the manifest), or null. */
    public function file(string $version, string $path): ?string
    {
        if ($this->manifest === null || $version !== $this->manifest['version'] || !isset($this->manifest['files'][$path]) || !ReleaseManifest::validPath($path)) {
            return null;
        }
        $full = $this->root . '/' . $path;
        if (is_link($full) || !is_file($full) || filesize($full) > ReleaseManifest::MAX_FILE_BYTES) {
            return null;
        }
        $content = (string) file_get_contents($full);
        // A file changed since signing would be refused by the agent anyway; refuse it here with a clearer error.
        return hash_equals($this->manifest['files'][$path], hash('sha256', $content)) ? $content : null;
    }
}

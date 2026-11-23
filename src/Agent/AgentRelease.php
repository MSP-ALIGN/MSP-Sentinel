<?php

declare(strict_types=1);

namespace Sentinel\Agent;

use Sentinel\System\ReleaseManifest;

/**
 * Sentinel's side of agent updates: whether this installation holds a SIGNED agent release, and serving its manifest
 * and files to agents. Sentinel only relays: agents (and their root update helper) accept the release only when it is
 * signed with the maintainer's release key they pinned at install. Sentinel never signs anything here.
 *
 * Where the release comes from: this installation's own files (the release tree it runs), with
 * release/agent-manifest.json + .sig and install/release-key.pub. A release is offered only when the signature checks
 * with that key and its version is this installation's version (a stale manifest from an older release isn't offered).
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

    public function __construct(private readonly string $root, private readonly string $appVersion, private readonly bool $anyVersion = false)
    {
        $json = (string) @file_get_contents($root . '/release/agent-manifest.json');
        $sig = trim((string) @file_get_contents($root . '/release/agent-manifest.sig'));
        $key = trim((string) @file_get_contents($root . '/install/release-key.pub'));
        if ($key === '') {
            $this->why = 'no release key (install/release-key.pub) in this installation';
            return;
        }
        if ($json === '') {
            $this->why = 'this version is not signed (no release/agent-manifest.json)';
            return;
        }
        $m = ReleaseManifest::verify($json, $sig, $key);
        if (is_string($m)) {
            $this->why = $m;
            return;
        }
        if (!$anyVersion && $m['version'] !== $appVersion) {
            $this->why = 'the signed release is ' . $m['version'] . ', not this installation\'s ' . $appVersion;
            return;
        }
        [$this->manifest, $this->json, $this->signature] = [$m, $json, $sig];
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

<?php

declare(strict_types=1);

namespace Sentinel\AgentClient;

use Sentinel\System\ReleaseManifest;

/**
 * Stages an agent update (the unprivileged agent's part). The agent can't change its own code (root-owned, read-only
 * for the service); it only prepares the new release in its state folder and asks the root update helper
 * (bin/agent-update-runner.php, started by a systemd path unit) to install it. The helper checks everything again.
 *
 * Steps: fetch the release manifest and signature from Sentinel; check the signature with the PINNED release key
 * (/etc/sentinel-agent/release-key.pub, written by the installer, never taken from Sentinel or from the new code),
 * that it is the version asked for and newer than this one; download every file and check its SHA-256; write the
 * request. Anything unexpected stops the update and is reported; nothing is installed half-way.
 *
 * Untrusted: everything from Sentinel (manifest, files). The release key decides.
 */
final class Updater
{
    /**
     * @param callable(string):void $log
     * @param string $serverKey  the pinned server key (update requests from Sentinel are signed with it)
     */
    public function __construct(private readonly Http $http, private readonly string $releaseKeyFile, private readonly string $stateDir, private $log,
        private readonly string $serverKey = '', private readonly int $agentId = 0, private readonly int $siteId = 0, private readonly int $clientId = 0)
    {
    }

    /**
     * The version and request identifier a signed update request (from a check-in answer) asks for, or null when it
     * isn't one for this agent. Sentinel's signature only says "this server asks"; the code itself is checked against
     * the release key later. The identifier travels with the result, so Sentinel can tell which request it answers.
     *
     * @param array<string,mixed> $signed
     * @return array{0:string, 1:string}|null
     */
    public function requested(array $signed): ?array
    {
        if (!is_string($signed['payload'] ?? null) || !is_string($signed['signature'] ?? null) || !\Sentinel\Agent\Signer::verify($signed['payload'], $signed['signature'], $this->serverKey)) {
            return null;
        }
        $d = json_decode($signed['payload'], true);
        $issued = is_array($d) ? strtotime((string) ($d['issued_at'] ?? '')) : false;
        if (!is_array($d) || ($d['type'] ?? null) !== 'agent_update' || ($d['agent_id'] ?? null) !== $this->agentId || ($d['site_id'] ?? null) !== $this->siteId
            || ($d['client_id'] ?? null) !== $this->clientId || !is_string($d['version'] ?? null) || $issued === false || abs(time() - $issued) > 3600) {
            return null;
        }
        return [$d['version'], is_string($d['request'] ?? null) ? mb_substr($d['request'], 0, 30) : ''];
    }

    /** Whether an update is staged and waiting for the helper (don't stage again meanwhile). */
    public function pending(): bool
    {
        return is_file($this->stateDir . '/update-request');
    }

    /** Forget the helper's result once Sentinel has it. */
    public function clearResult(): void
    {
        @unlink($this->stateDir . '/update-result.json');
    }

    /** Whether this agent can be updated remotely (a release key is pinned). */
    public function available(): bool
    {
        return is_readable($this->releaseKeyFile) && trim((string) file_get_contents($this->releaseKeyFile)) !== '';
    }

    /**
     * Stage version $target and ask the helper to install it. Returns '' when staged, else why not.
     */
    public function stage(string $target, string $current, string $request = ''): string
    {
        if (!$this->available()) {
            return 'No release key is pinned on this agent: upgrade it once by hand (agent-install.sh --upgrade).';
        }
        if (!ReleaseManifest::newer($target, $current)) {
            return 'Version ' . $target . ' is not newer than ' . $current . '.';
        }
        $res = $this->http->post('/agent/v1/update/manifest', ['version' => $target], 60);
        $json = is_string($res['data']['manifest'] ?? null) ? $res['data']['manifest'] : '';
        $sig = is_string($res['data']['signature'] ?? null) ? $res['data']['signature'] : '';
        if ($res['status'] !== 200 || $json === '') {
            return 'Sentinel has no signed release for ' . $target . '.';
        }
        $m = ReleaseManifest::verify($json, $sig, (string) file_get_contents($this->releaseKeyFile));
        if (is_string($m)) {
            return 'Release refused: ' . $m . '.';
        }
        if ($m['version'] !== $target) {
            return 'Release refused: it is version ' . $m['version'] . ', not ' . $target . '.';
        }
        $dir = $this->stateDir . '/update';
        self::removeTree($dir);
        if (!mkdir($dir . '/files', 0700, true)) {
            return 'Could not prepare the update folder.';
        }
        foreach ($m['files'] as $path => $hash) {
            $r = $this->http->post('/agent/v1/update/file', ['version' => $target, 'path' => $path], 120);
            $content = is_string($r['data']['content'] ?? null) ? base64_decode($r['data']['content'], true) : false;
            if ($r['status'] !== 200 || $content === false || strlen($content) > ReleaseManifest::MAX_FILE_BYTES || !hash_equals($hash, hash('sha256', $content))) {
                self::removeTree($dir);
                return 'Release refused: ' . $path . ' does not match the signed release.';
            }
            $dest = $dir . '/files/' . $path;
            if (!is_dir(dirname($dest)) && !mkdir(dirname($dest), 0700, true)) {
                self::removeTree($dir);
                return 'Could not prepare the update folder.';
            }
            file_put_contents($dest, $content);
        }
        file_put_contents($dir . '/agent-manifest.json', $json);
        file_put_contents($dir . '/agent-manifest.sig', $sig);
        @unlink($this->stateDir . '/update-result.json');
        // The request the root helper watches for (systemd path unit). Written last, atomically.
        file_put_contents($this->stateDir . '/update-request.tmp', json_encode(['version' => $m['version'], 'request' => $request]));
        rename($this->stateDir . '/update-request.tmp', $this->stateDir . '/update-request');
        ($this->log)('Update to ' . $m['version'] . ' staged (' . count($m['files']) . ' files, signature and hashes checked); the update helper installs it.');
        return '';
    }

    /** The helper's last result (version, ok, message), if any. @return array<string,mixed>|null */
    public function lastResult(): ?array
    {
        $r = json_decode((string) @file_get_contents($this->stateDir . '/update-result.json'), true);
        return is_array($r) ? $r : null;
    }

    /** Remove a folder this class made (no symlinks followed). */
    public static function removeTree(string $dir): void
    {
        if (!is_dir($dir) || is_link($dir)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $f->isDir() && !$f->isLink() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
        }
        @rmdir($dir);
    }
}

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
        private readonly string $serverKey = '', private readonly int $agentId = 0, private readonly int $siteId = 0, private readonly int $clientId = 0,
        private readonly string $resultDir = '/var/lib/sentinel-agent-update', private readonly string $configKey = '')
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

    /**
     * Whether an update is staged and waiting for the helper (don't stage again meanwhile). A request the helper already
     * answered (its result names the request), or one older than an hour, is removed here: the agent cleans up its
     * own folder, so a request left behind never blocks later updates.
     */
    public function pending(): bool
    {
        $file = $this->stateDir . '/update-request';
        if (!is_file($file)) {
            return false;
        }
        $req = json_decode((string) @file_get_contents($file, false, null, 0, 4096), true);
        $res = json_decode((string) @file_get_contents($this->resultDir . '/result.json', false, null, 0, 8192), true);
        $asked = is_array($req) ? ($req['version'] ?? (($req['kind'] ?? '') === 'pin' ? 'release-key' : false)) : false;
        $answered = is_array($req) && is_array($res) && ($res['request'] ?? null) === ($req['request'] ?? false) && ($res['version'] ?? null) === $asked;
        if ($answered || (int) @filemtime($file) < time() - 3600) {
            @unlink($file);
            return false;
        }
        return true;
    }

    /**
     * Sentinel has this result now: don't send it again, and clean up the staged files (the agent's own folder: the
     * root helper never deletes anything there).
     *
     * @param array<string,mixed> $result
     */
    public function markReported(array $result): void
    {
        file_put_contents($this->stateDir . '/update-reported', self::resultId($result));
        self::removeTree($this->stateDir . '/update');
        @unlink($this->stateDir . '/update-result.json'); // a 1.22.0 helper's result, in the agent's own folder
    }

    /** Whether this agent can be updated remotely (a release key is pinned). */
    public function available(): bool
    {
        return $this->releaseKey() !== '';
    }

    /**
     * The pinned release key: the root-owned key file (written by the installer or the root update helper), else the one
     * in the root-owned config (given at enrolment). Never anything the agent itself can write.
     */
    public function releaseKey(): string
    {
        $file = is_readable($this->releaseKeyFile) ? trim((string) file_get_contents($this->releaseKeyFile, false, null, 0, 1024)) : '';
        return $file !== '' ? $file : trim($this->configKey);
    }

    /**
     * An offer of the release key from Sentinel (signed with the pinned server key, for this agent, recent): hand it to
     * the root update helper, which checks it again and pins it (only when none is pinned, or with a rotation statement
     * signed by the pinned key). Returns whether it was handed over.
     *
     * @param array<string,mixed> $signed
     */
    public function stagePin(array $signed): bool
    {
        if ($this->pending() || !is_string($signed['payload'] ?? null) || !is_string($signed['signature'] ?? null)
            || !\Sentinel\Agent\Signer::verify($signed['payload'], $signed['signature'], $this->serverKey)) {
            return false;
        }
        $d = json_decode($signed['payload'], true);
        $issued = is_array($d) ? strtotime((string) ($d['issued_at'] ?? '')) : false;
        if (!is_array($d) || ($d['type'] ?? null) !== 'agent_release_key' || ($d['agent_id'] ?? null) !== $this->agentId || ($d['site_id'] ?? null) !== $this->siteId
            || ($d['client_id'] ?? null) !== $this->clientId || !is_string($d['key'] ?? null) || !ReleaseManifest::validPublicKey($d['key']) || $issued === false
            || abs(time() - $issued) > 3600 || $d['key'] === $this->releaseKey()) {
            return false;
        }
        file_put_contents($this->stateDir . '/release-key-offer.json', json_encode($signed, JSON_UNESCAPED_SLASHES));
        file_put_contents($this->stateDir . '/update-request.tmp', json_encode(['kind' => 'pin', 'request' => (string) $d['issued_at']]));
        rename($this->stateDir . '/update-request.tmp', $this->stateDir . '/update-request');
        ($this->log)('Release key offered by Sentinel (' . ReleaseManifest::keyFingerprint($d['key']) . '); the update helper checks and pins it.');
        return true;
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
        $m = ReleaseManifest::verify($json, $sig, $this->releaseKey());
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
        // The request the root helper watches for (systemd path unit). Written last, atomically.
        file_put_contents($this->stateDir . '/update-request.tmp', json_encode(['version' => $m['version'], 'request' => $request]));
        rename($this->stateDir . '/update-request.tmp', $this->stateDir . '/update-request');
        ($this->log)('Update to ' . $m['version'] . ' staged (' . count($m['files']) . ' files, signature and hashes checked); the update helper installs it.');
        return '';
    }

    /** The helper's last result (version, ok, message, request, at) when not reported yet. @return array<string,mixed>|null */
    public function unreportedResult(): ?array
    {
        $r = json_decode((string) @file_get_contents($this->resultDir . '/result.json', false, null, 0, 8192), true);
        if (!is_array($r) || !is_string($r['version'] ?? null)) {
            // A result an agent update helper of 1.22.0 left in the agent's own folder (read once, then removed).
            $r = json_decode((string) @file_get_contents($this->stateDir . '/update-result.json', false, null, 0, 8192), true);
            if (!is_array($r) || !is_string($r['version'] ?? null)) {
                return null;
            }
        }
        if (trim((string) @file_get_contents($this->stateDir . '/update-reported')) === self::resultId($r)) {
            return null;
        }
        if (($r['version'] ?? '') === 'release-key') {
            // The helper pinning a release key: logged here; Sentinel sees the new key's fingerprint at the next check-in.
            ($this->log)('Release key: ' . mb_substr((string) ($r['message'] ?? ''), 0, 200));
            $this->markReported($r);
            return null;
        }
        return $r;
    }

    /** @param array<string,mixed> $r */
    private static function resultId(array $r): string
    {
        return hash('sha256', (string) ($r['version'] ?? '') . '|' . (string) ($r['request'] ?? '') . '|' . (string) ($r['at'] ?? ''));
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

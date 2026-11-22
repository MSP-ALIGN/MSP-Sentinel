<?php

declare(strict_types=1);

namespace Sentinel\System;

/**
 * "Update now" from the web interface, without giving the web app any privileges.
 *
 * How it works:
 * - The web app (unprivileged) only creates an empty request file in storage/ (request()).
 * - A root-owned systemd path unit on the server notices the file, deletes it without reading it, and runs
 *   msp-sentinel-update (the same command an administrator runs over SSH: backup first, fetch the branch the
 *   server follows, migrate, health check). See install/templates/msp-sentinel-update-runner.
 * - The runner writes its progress to a root-owned state directory (default /var/lib/msp-sentinel-update,
 *   mode 0750 root:sentinel) that the web app can read but not write: status.json and update.log.
 * - The installer creates the state directory and an "enabled" marker only on installs made with the one-line
 *   installer (they have msp-sentinel-update). The server administrator turns it off by stopping the path unit
 *   and removing the marker (docs/upgrade.md); nothing in the web interface can turn it back on.
 *
 * Security assumptions:
 * - The request file carries no data, so nothing the web app writes ever reaches the root process. The runner
 *   only removes it (removing a symlink is harmless) and always runs the same fixed command.
 * - The root process never writes into a directory the web app can write to (no symlink tricks).
 * - The caller (SystemController) checks the admin role and CSRF before request(); the runner allows one start
 *   every 15 minutes and only ever runs the fixed update.
 * - status.json and update.log are read as untrusted text: status fields are checked against patterns, and the
 *   log is size-capped, scrubbed of control characters and escaped by the view.
 */
final class WebUpdate
{
    /** Longer than this "running" means the runner was stopped (e.g. a reboot): offer to try again. */
    private const STALE_SECONDS = 3 * 3600;

    public function __construct(private readonly string $stateDir, private readonly string $requestFile)
    {
    }

    /** Whether the server has the update runner (installed by the one-line installer and not turned off). */
    public function available(): bool
    {
        return is_file($this->stateDir . '/enabled');
    }

    /** Whether a request is waiting for the runner to pick it up. */
    public function pending(): bool
    {
        return file_exists($this->requestFile) || is_link($this->requestFile);
    }

    /**
     * The runner's last status: state (idle, running, done, failed), start and finish times (UTC) and exit code.
     *
     * @return array{state:string, started:string, finished:string, exit:int, stale:bool}
     */
    public function status(): array
    {
        $raw = @file_get_contents($this->stateDir . '/status.json', false, null, 0, 2048);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        $time = static fn ($v): string => is_string($v) && preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $v) === 1 ? $v : '';
        $state = is_array($data) && in_array($data['state'] ?? '', ['running', 'done', 'failed'], true) ? (string) $data['state'] : 'idle';
        $started = $time($data['started'] ?? null);
        return [
            'state' => $state, 'started' => $started, 'finished' => $time($data['finished'] ?? null),
            'exit' => is_int($data['exit'] ?? null) ? $data['exit'] : 0,
            'stale' => $state === 'running' && $started !== '' && strtotime($started . ' UTC') < time() - self::STALE_SECONDS,
        ];
    }

    /** The end of the last update's output (at most 16 KB), scrubbed of control characters. */
    public function log(): string
    {
        $path = $this->stateDir . '/update.log';
        $size = @filesize($path);
        if ($size === false || $size === 0) {
            return '';
        }
        $raw = (string) @file_get_contents($path, false, null, max(0, $size - 16384), 16384);
        $raw = preg_replace('/\e\[[0-9;]*[A-Za-z]/', '', $raw) ?? ''; // colour codes from the installer
        return trim((string) preg_replace('/[^\P{C}\n\t]/u', '', mb_scrub($raw, 'UTF-8')));
    }

    /**
     * Ask the runner to update. False when updates from the web are not set up, or one is already waiting or running.
     */
    public function request(): bool
    {
        if (!$this->available() || $this->pending()) {
            return false;
        }
        $s = $this->status();
        if ($s['state'] === 'running' && !$s['stale']) {
            return false;
        }
        // Exclusive create: never follows or overwrites an existing file. Empty on purpose (see the class notes).
        $h = @fopen($this->requestFile, 'x');
        if ($h === false) {
            return false;
        }
        fclose($h);
        return true;
    }
}

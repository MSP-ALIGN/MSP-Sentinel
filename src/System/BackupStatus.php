<?php

declare(strict_types=1);

namespace Sentinel\System;

use Sentinel\Core\Settings;

/**
 * What the nightly backup job did (1.37): bin/backup.php records each run (when, success, size, encrypted, file name or
 * error) in the setting backup_history, newest first, at most HISTORY runs. The System page lists them; the health check
 * and the daily housekeeping (an admin alert, at most once a day) say when the last run failed or the last good backup
 * is older than STALE_HOURS.
 *
 * Untrusted: nothing from outside (values come from the backup job; the stored JSON is decoded defensively anyway).
 * Security assumptions: only the file's base name is kept (no folder, never the passphrase); the error text is the
 * backup job's own message, shortened.
 */
final class BackupStatus
{
    public const HISTORY = 10;
    /** A good backup older than this is a problem (the job runs nightly; two missed nights). */
    public const STALE_HOURS = 48;

    public function __construct(private readonly Settings $settings)
    {
    }

    /** Record one run of the backup job. */
    public function record(bool $ok, string $file, int $bytes, bool $encrypted, string $error = ''): void
    {
        $entry = ['at' => gmdate('Y-m-d H:i:s'), 'ok' => $ok, 'file' => mb_substr(basename($file), 0, 120), 'bytes' => max(0, $bytes),
                  'encrypted' => $encrypted, 'error' => mb_substr($error, 0, 300)];
        $this->settings->set('backup_history', (string) json_encode(array_slice([$entry, ...$this->history()], 0, self::HISTORY), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
    }

    /**
     * The recorded runs, newest first.
     *
     * @return list<array{at:string, ok:bool, file:string, bytes:int, encrypted:bool, error:string}>
     */
    public function history(): array
    {
        $raw = json_decode($this->settings->fresh('backup_history'), true);
        $out = [];
        foreach (is_array($raw) ? $raw : [] as $r) {
            if (is_array($r) && is_string($r['at'] ?? null) && preg_match('/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/', $r['at']) === 1) {
                $out[] = ['at' => $r['at'], 'ok' => ($r['ok'] ?? false) === true, 'file' => (string) ($r['file'] ?? ''), 'bytes' => (int) ($r['bytes'] ?? 0),
                          'encrypted' => ($r['encrypted'] ?? false) === true, 'error' => (string) ($r['error'] ?? '')];
            }
        }
        return $out;
    }

    /**
     * What is wrong, or null: the last run failed, or the last good backup is older than STALE_HOURS (or there is none
     * while runs were recorded). Null when nothing was ever recorded (the health check says that separately).
     */
    public function problem(?int $now = null): ?string
    {
        $now ??= time();
        $h = $this->history();
        if ($h === []) {
            return null;
        }
        if (!$h[0]['ok']) {
            return __('The last backup ({t} UTC) failed: {e}', ['t' => $h[0]['at'], 'e' => $h[0]['error'] !== '' ? $h[0]['error'] : __('no details')]);
        }
        $lastOk = null;
        foreach ($h as $r) {
            if ($r['ok']) {
                $lastOk = $r['at'];
                break;
            }
        }
        if ($lastOk === null || strtotime($lastOk . ' UTC') < $now - self::STALE_HOURS * 3600) {
            return __('No good backup in the last {n} hours (last: {t} UTC). Check the backup cron job and /var/log/msp-sentinel.', ['n' => self::STALE_HOURS, 't' => $lastOk ?? __('never')]);
        }
        return null;
    }
}

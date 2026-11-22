<?php

declare(strict_types=1);

namespace Sentinel\Findings;

use PDO;

/**
 * The honest result of a "verify fix" recheck, and recording it.
 *
 * A result is only "fixed" or "still present" when THIS recheck conclusively
 * checked the finding's own target:
 * - the job finished completely and the findings refresh succeeded;
 * - the port was scanned completely (open, or not reachable any more);
 * - for certificates the certificate check of that host name succeeded; for
 *   web pages the page was fetched; for website checks the exposed-file run
 *   was complete; for vulnerabilities no vulnerability data was pending;
 *   for email records the DNS lookups succeeded.
 * "Fixed" also needs the finding to have been resolved by this recheck (not
 * before it started). A certificate, web or vulnerability finding on a port
 * that no longer answers is "no longer reachable", not "fixed". Anything else
 * is "not verified", with the reason.
 *
 * Untrusted: the job summary was written by the worker from scan results;
 * only fixed keys and types are read from it.
 */
final class VerifyOutcome
{
    public const RESULTS = ['fixed', 'still_present', 'unreachable', 'already_resolved', 'not_verified'];

    /**
     * Decide the result.
     *
     * @param array<string,mixed> $finding  Current finding row (finding_key, status, resolved_at).
     * @param string              $jobStatus done|partial|failed|cancelled
     * @param string|null         $startedAt When the job started (UTC), from scan_jobs.
     * @param array<string,mixed> $summary  Job summary: verify_probe (per "ip:port" or "email"), refresh_ok, vuln_pending, messages.
     * @return array{result:string, note:string}
     */
    public static function decide(array $finding, string $jobStatus, ?string $startedAt, array $summary): array
    {
        $key = (string) $finding['finding_key'];
        $target = VerifyTarget::fromKey($key);
        $resolved = $finding['status'] === 'resolved';
        $resolvedHere = $resolved && $startedAt !== null && $finding['resolved_at'] !== null && strtotime($finding['resolved_at'] . ' UTC') >= strtotime($startedAt . ' UTC');
        $why = static fn (string $reason): array => ['result' => 'not_verified', 'note' => __('Verify fix could not finish: {why}', ['why' => $reason])];
        if ($resolved && !$resolvedHere) {
            return ['result' => 'already_resolved', 'note' => __('Verify fix: the finding was already resolved by another check before this recheck ran.')];
        }
        if ($jobStatus !== 'done') {
            $msg = implode(' ', array_slice(array_map('strval', (array) ($summary['messages'] ?? [])), 0, 2));
            return $why($msg !== '' ? $msg : __('the recheck did not complete.'));
        }
        if (($summary['refresh_ok'] ?? false) !== true) {
            return $why(__('the findings could not be updated (another update was running). Try again.'));
        }
        if ($target === null) {
            return $why(__('this finding cannot be rechecked on its own.'));
        }
        $probe = (array) ($summary['verify_probe'] ?? []);
        $yes = ['result' => $resolvedHere ? 'fixed' : 'still_present',
                'note' => $resolvedHere ? __('Verify fix: the problem is no longer seen. Resolved.') : __('Verify fix: the problem is still seen.')];
        if ($target['kind'] === 'email') {
            return ($probe['email'] ?? null) === 'ok' ? $yes : $why(__('the DNS lookups did not succeed.'));
        }
        $p = (array) ($probe[$target['ip'] . ':' . $target['port']] ?? []);
        $state = $p['state'] ?? 'unknown';
        $prefix = (string) strtok($key, ':');
        if ($state === 'unknown') {
            return $why(__('the port could not be scanned completely.'));
        }
        if ($prefix === 'port') {
            if ($state === 'closed') {
                return $resolvedHere ? ['result' => 'fixed', 'note' => __('Verify fix: the port is no longer reachable from the internet. Resolved.')] : $why(__('the port no longer answers, but the finding is still open.'));
            }
            return $yes;
        }
        if ($state === 'closed') {
            return ['result' => 'unreachable', 'note' => __('Verify fix: nothing answers on this port any more, so the finding no longer applies. It was not possible to check whether the problem itself was fixed.')];
        }
        $ok = match ($prefix) {
            'tls' => ($p['tls_ok'] ?? false) === true && in_array(self::sni($key), (array) ($p['snis'] ?? []), true),
            'web' => ($p['web_ok'] ?? false) === true,
            'site' => ($p['web_ok'] ?? false) === true && ($p['site_complete'] ?? false) === true,
            'webvuln' => ($p['web_ok'] ?? false) === true && ($summary['vuln_pending'] ?? -1) === 0,
            'vuln' => ($summary['vuln_pending'] ?? -1) === 0,
            default => false,
        };
        if (!$ok) {
            return $why(match ($prefix) {
                'tls' => __('the certificate check did not succeed for this host name.'),
                'web', 'site' => __('the web page or the website checks did not complete.'),
                default => __('vulnerability data for this software is still being fetched. Try again after the daily feeds job.'),
            });
        }
        return $yes;
    }

    /**
     * Record the result in the finding's history and notify the person who asked (if any).
     */
    public static function record(PDO $db, int $findingId, ?int $requestedBy, string $result, string $note): void
    {
        $title = (string) $db->query('SELECT title FROM findings WHERE id = ' . $findingId)->fetchColumn();
        if ($title === '') {
            return;
        }
        $db->prepare("INSERT INTO finding_events (finding_id, event, user_id, note, created_at) VALUES (:f, 'verified', NULL, :n, UTC_TIMESTAMP())")
            ->execute(['f' => $findingId, 'n' => mb_substr($note, 0, 1000)]);
        if ($requestedBy === null) {
            return;
        }
        $label = match ($result) {
            'fixed' => __('Fixed: {title}', ['title' => $title]),
            'still_present' => __('Still present: {title}', ['title' => $title]),
            'unreachable' => __('No longer reachable: {title}', ['title' => $title]),
            'already_resolved' => __('Already resolved: {title}', ['title' => $title]),
            default => __('Not verified: {title}', ['title' => $title]),
        };
        $db->prepare('INSERT INTO notifications (user_id, kind, severity, title, body, link, created_at) VALUES (:u, :k, :s, :t, :b, :l, UTC_TIMESTAMP())')
            ->execute(['u' => $requestedBy, 'k' => 'verify', 's' => in_array($result, ['fixed', 'already_resolved'], true) ? 'info' : 'warn',
                       't' => mb_substr($label, 0, 300), 'b' => mb_substr($note, 0, 2000), 'l' => '/findings/' . $findingId]);
    }

    /**
     * Record "not verified" for a verify job that ended without running (cancelled, paused, worker died).
     *
     * @param array<string,mixed> $job scan_jobs row with decoded payload.
     */
    public static function recordAborted(PDO $db, array $job, string $reason): void
    {
        if (($job['job_type'] ?? '') !== 'verify') {
            return;
        }
        $findingId = (int) ($job['payload']['finding_id'] ?? 0);
        $owned = $db->prepare('SELECT COUNT(*) FROM findings WHERE id = :f AND client_id = :c');
        $owned->execute(['f' => $findingId, 'c' => (int) $job['client_id']]);
        if ((int) $owned->fetchColumn() !== 1) {
            return;
        }
        self::record($db, $findingId, $job['requested_by'] === null ? null : (int) $job['requested_by'], 'not_verified', __('Verify fix could not finish: {why}', ['why' => $reason]));
    }

    /** The host name part of a certificate finding key ("tls:{ip}:{port}:{sni}:{code}"). */
    private static function sni(string $key): string
    {
        $parts = explode(':', $key);
        return (string) ($parts[count($parts) - 2] ?? '');
    }
}

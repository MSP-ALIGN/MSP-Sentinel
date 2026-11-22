<?php

declare(strict_types=1);

namespace Sentinel\Vulns;

use Sentinel\Core\Settings;

/**
 * When the vulnerability data (CISA KEV, NVD, EPSS) is refreshed. The installer's cron job runs
 * "bin/feeds.php --if-due" every 5 minutes; it only does the work when it is due: never refreshed yet, the last
 * run started 20 or more hours ago, or someone asked for a refresh ("Refresh now") since the last run started.
 * So a new server gets its data within minutes, and a manual refresh starts within 5 minutes.
 *
 * State lives in settings (feeds_run_started, feeds_run_finished, feeds_requested_at, all UTC). The run itself is
 * kept single by a database lock in bin/feeds.php.
 *
 * Untrusted input: none (times are written by this class; anything else stored there is ignored).
 */
final class FeedSchedule
{
    /** Hours between scheduled refreshes. */
    public const INTERVAL_HOURS = 20;

    public function __construct(private readonly Settings $settings)
    {
    }

    /** Whether bin/feeds.php --if-due should run now. */
    public function due(?int $now = null): bool
    {
        $now ??= time();
        $started = $this->time('feeds_run_started');
        $requested = $this->time('feeds_requested_at');
        return $started === null || $started <= $now - self::INTERVAL_HOURS * 3600 || ($requested !== null && $requested >= $started);
    }

    /** Ask for a refresh (Refresh now). */
    public function request(): void
    {
        $this->settings->set('feeds_requested_at', gmdate('Y-m-d H:i:s'));
    }

    /** Called by bin/feeds.php when a run starts (this also answers any request made before now). */
    public function started(): void
    {
        $this->settings->set('feeds_run_started', gmdate('Y-m-d H:i:s'));
        $this->settings->set('feeds_run_finished', '');
        $this->settings->set('feeds_requested_at', ''); // this run answers the request
    }

    /** Called by bin/feeds.php when a run ends. */
    public function finished(): void
    {
        $this->settings->set('feeds_run_finished', gmdate('Y-m-d H:i:s'));
    }

    /**
     * For the pages: requested (waiting), running, last started and finished.
     *
     * @return array{requested:bool, running:bool, started:string, finished:string}
     */
    public function status(): array
    {
        $started = $this->time('feeds_run_started');
        $finished = $this->time('feeds_run_finished');
        $requested = $this->time('feeds_requested_at');
        // "Running" while a start has no finish yet, for at most 3 hours (a crashed run doesn't stay "running").
        $running = $started !== null && $finished === null && $started > time() - 3 * 3600;
        return [
            'requested' => $requested !== null && ($started === null || $requested >= $started),
            'running' => $running,
            'started' => $started === null ? '' : gmdate('Y-m-d H:i:s', $started),
            'finished' => $finished === null ? '' : gmdate('Y-m-d H:i:s', $finished),
        ];
    }

    /** A stored UTC time as Unix time, or null. */
    private function time(string $name): ?int
    {
        $v = $this->settings->fresh($name);
        return preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $v) === 1 ? (int) strtotime($v . ' UTC') : null;
    }
}

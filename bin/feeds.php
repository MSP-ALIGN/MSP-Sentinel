<?php

declare(strict_types=1);

/**
 * CLI: refresh vulnerability data and re-match every open service.
 *
 *   php bin/feeds.php            refresh now
 *   php bin/feeds.php --if-due   refresh only when due (see Vulns\FeedSchedule): the installer's cron job runs this
 *                                every 5 minutes, so data arrives within minutes of installing and "Refresh now"
 *                                in the web interface starts within 5 minutes. Otherwise it refreshes daily.
 *
 * Only one run at a time (database lock): a run that finds another one going exits at once.
 *
 * Steps: CISA KEV catalog -> NVD product queries that are new or older than
 * 7 days (rate-limited) -> re-match all services -> EPSS scores for matched CVEs.
 * Each step reports its own result, so one feed being down doesn't stop the others.
 *
 * Security assumptions: CLI only. Only public feeds are contacted (configured
 * base URLs). No client system is touched.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/src/bootstrap.php';

use Sentinel\Core\App;

try {
    App::boot();
    $schedule = new \Sentinel\Vulns\FeedSchedule(App::settings());
    $opts = getopt('', ['if-due']);
    if (isset($opts['if-due']) && !$schedule->due()) {
        exit(0); // not due: nothing to do (this runs every 5 minutes)
    }
    $lock = App::db()->quote('msp_sentinel_feeds_' . substr(hash('sha256', (string) App::db()->query('SELECT DATABASE()')->fetchColumn()), 0, 16));
    if ((int) App::db()->query("SELECT GET_LOCK({$lock}, 0)")->fetchColumn() !== 1) {
        fwrite(STDOUT, "Another feeds run is still going.\n");
        exit(0);
    }
    $schedule->started();
    register_shutdown_function(static function () use ($schedule): void {
        try {
            $schedule->finished();
        } catch (\Throwable) {
            // the database went away: the next run starts over
        }
    });
    fwrite(STDOUT, '[' . gmdate('Y-m-d H:i:s') . "] Refreshing vulnerability data\n");
    $updater = App::feedUpdater();
    $exit = 0;
    $alerts = App::alerts();
    try {
        fwrite(STDOUT, 'KEV: ' . $updater->refreshKev() . " entries\n");
    } catch (\RuntimeException $ex) {
        fwrite(STDOUT, 'KEV failed: ' . $ex->getMessage() . "\n");
        $alerts->feedFailed('kev', $ex->getMessage());
        $exit = 1;
    }
    $nvd = $updater->refreshNvd((int) App::config()->get('nvd.max_queries_per_run', 500));
    fwrite(STDOUT, "NVD: {$nvd['ok']} queries fetched, {$nvd['failed']} failed\n");
    $exit = $nvd['failed'] > 0 ? 1 : $exit;
    if ($nvd['blocked']) {
        $alerts->feedFailed('nvd', 'NVD asked Sentinel to slow down; the remaining lookups will run later.');
    }
    $m = App::vulnMatcher()->matchClient(null, 0);
    fwrite(STDOUT, "Matching: {$m['services']} services, {$m['matches']} matches, {$m['pending']} waiting for data\n");
    $wm = App::vulnMatcher()->matchComponents(new \Sentinel\Web\WebsiteRepository(App::db()), null, 0);
    fwrite(STDOUT, "Website components: {$wm['components']} checked, {$wm['matches']} matches, {$wm['pending']} waiting for data\n");
    $sm = App::vulnMatcher()->matchSoftware(App::inventory(), null, 0);
    fwrite(STDOUT, "Installed software: {$sm['products']} products, {$sm['matches']} matches, {$sm['pending']} waiting for data\n");
    try {
        fwrite(STDOUT, 'EPSS: ' . $updater->refreshEpss() . " scores\n");
    } catch (\RuntimeException $ex) {
        fwrite(STDOUT, 'EPSS failed: ' . $ex->getMessage() . "\n");
        $alerts->feedFailed('epss', $ex->getMessage());
        $exit = 1;
    }
    // New data can create or resolve findings (and accepted risks can be affected), so refresh them all.
    try {
        // New vulnerability data can create new Fail findings: alert on those (no digest from the feeds job).
        $n = App::findingsEngine()->refreshAll(static function (int $clientId, array $result) use ($alerts): void {
            $alerts->findingsChanged($clientId, $result, false);
        });
        fwrite(STDOUT, 'Findings: refreshed for ' . $n . " client(s)\n");
        (new \Sentinel\Reports\StatsRecorder(App::db()))->recordToday(true); // daily counts for report trends
        $sent = App::outbox()->flush(200);
        fwrite(STDOUT, "Alerts: {$sent['sent']} sent, {$sent['failed']} failed\n");
    } catch (\Throwable $ex) {
        fwrite(STDOUT, 'Findings failed: ' . $ex->getMessage() . "\n");
        $exit = 1;
    }
    exit($exit);
} catch (\Throwable $ex) {
    fwrite(STDERR, 'Feeds failed: ' . $ex->getMessage() . "\n");
    exit(1);
}

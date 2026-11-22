<?php

declare(strict_types=1);

/**
 * CLI: refresh vulnerability data and re-match every open service. Run daily from cron:
 *
 *   41 4 * * *  php /path/to/msp-sentinel/bin/feeds.php
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

<?php

declare(strict_types=1);

namespace Sentinel\Vulns;

use Sentinel\Core\Config;

/**
 * Refreshes the public threat feeds:
 * - NVD: answers to "which CVEs affect this product/version?" (CVE API 2.0,
 *   virtualMatchString), paginated, cached for 7 days. Requests are paced
 *   ACROSS processes (the time of the last request is kept in the database,
 *   under a lock): about 6 s apart without an API key, under 1 s with one.
 *   A 403, 429 or 503 stops all NVD requests until Retry-After has passed.
 * - CISA KEV: the full Known Exploited Vulnerabilities catalog (replaced each time);
 * - FIRST EPSS: exploit-probability scores for CVEs on open services.
 *
 * Security assumptions: these are public data sources. Nothing here contacts
 * client systems. Base URLs come from config only. The NVD API key (config
 * nvd.api_key) is sent as a header, and only to https or loopback URLs; it
 * is never logged or shown. NVD responses are untrusted (FeedParser validates them).
 */
final class FeedUpdater
{
    private const NVD_PAGE = 1000;
    private const NVD_MAX_PAGES = 10;
    private const EPSS_BATCH = 50;

    /** Use fromConfig() normally. */
    public function __construct(
        private readonly VulnRepository $repo,
        private readonly FeedHttp $http,
        private readonly string $nvdBase,
        private readonly ?string $nvdKey,
        private readonly string $kevUrl,
        private readonly string $epssBase,
        private readonly ?float $nvdDelayOverride = null,
    ) {
    }

    /**
     * Build from config: nvd.base_url, nvd.api_key, nvd.delay, kev.url, epss.base_url.
     *
     * @param int $timeout Per-request timeout (the scan worker uses a short one).
     */
    public static function fromConfig(Config $config, VulnRepository $repo, int $timeout = 60): self
    {
        $base = rtrim((string) $config->get('nvd.base_url', 'https://services.nvd.nist.gov'), '/');
        $delay = $config->get('nvd.delay');
        return new self(
            $repo,
            new FeedHttp($timeout),
            $base,
            self::usableKey($config, $base),
            (string) $config->get('kev.url', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
            rtrim((string) $config->get('epss.base_url', 'https://api.first.org'), '/'),
            is_numeric($delay) ? (float) $delay : null,
        );
    }

    /**
     * The configured NVD API key, if it is well formed and the NVD URL is
     * https or a loopback address (a key is never sent in cleartext elsewhere).
     */
    public static function usableKey(Config $config, ?string $base = null): ?string
    {
        $key = trim((string) $config->get('nvd.api_key', ''));
        $base ??= (string) $config->get('nvd.base_url', 'https://services.nvd.nist.gov');
        $host = (string) parse_url($base, PHP_URL_HOST);
        $safeTransport = parse_url($base, PHP_URL_SCHEME) === 'https' || in_array($host, ['127.0.0.1', 'localhost', '::1', '[::1]'], true);
        return $safeTransport && preg_match('/^[A-Za-z0-9-]{20,64}$/D', $key) ? $key : null;
    }

    /**
     * Fetch one CPE query from NVD and store the result.
     *
     * @param string $query Match string built by Cpe (validated, escaped).
     * @return bool True on success (failures are recorded on the query).
     * @throws RateLimited when NVD refuses requests (the caller must stop fetching).
     */
    public function fetchQuery(string $query): bool
    {
        $prefix = Cpe::productPrefix($query);
        try {
            $cves = [];
            $total = 0;
            for ($page = 0; $page < self::NVD_MAX_PAGES; $page++) {
                $this->nvdPace();
                $url = $this->nvdBase . '/rest/json/cves/2.0?' . http_build_query([
                    'virtualMatchString' => $query, 'startIndex' => $page * self::NVD_PAGE, 'resultsPerPage' => self::NVD_PAGE,
                ]);
                $parsed = FeedParser::nvdPage($this->http->getJson($url, $this->nvdKey !== null ? ['apiKey: ' . $this->nvdKey] : []), $prefix);
                $total = $parsed['total'];
                foreach ($parsed['cves'] as $cve) {
                    $cves[$cve['cve_id']] = $cve;
                }
                if (($page + 1) * self::NVD_PAGE >= $total) {
                    break;
                }
            }
            $note = $total > self::NVD_PAGE * self::NVD_MAX_PAGES
                ? sprintf('Only the first %d of %d NVD results were read.', self::NVD_PAGE * self::NVD_MAX_PAGES, $total) : '';
            $this->repo->storeQueryResult($query, array_values($cves), $note);
            return true;
        } catch (RateLimited $ex) {
            $this->repo->setNvdBlockedUntil(time() + $ex->retryAfterSeconds);
            $this->repo->markQueryError($query, $ex->getMessage());
            throw $ex;
        } catch (\RuntimeException $ex) {
            $this->repo->markQueryError($query, $ex->getMessage());
            return false;
        }
    }

    /** True while NVD has asked us to back off. */
    public function nvdBlocked(): bool
    {
        return $this->repo->nvdBlockedUntil() > time();
    }

    /**
     * Fetch due NVD queries (pending, failed, or older than 7 days, and still needed).
     * Stops at the first rate-limit answer.
     *
     * @return array{ok:int, failed:int, blocked:bool}
     */
    public function refreshNvd(int $limit): array
    {
        $ok = $failed = 0;
        if ($this->nvdBlocked()) {
            $this->repo->feedStatus('nvd', false, 'NVD asked us to wait; skipped this run.');
            return ['ok' => 0, 'failed' => 0, 'blocked' => true];
        }
        try {
            foreach ($this->repo->dueQueries($limit) as $query) {
                $this->fetchQuery($query) ? $ok++ : $failed++;
            }
        } catch (RateLimited $ex) {
            $this->repo->feedStatus('nvd', false, "Fetched {$ok}, then NVD asked us to wait: " . $ex->getMessage());
            return ['ok' => $ok, 'failed' => $failed + 1, 'blocked' => true];
        }
        $this->repo->feedStatus('nvd', $failed === 0, $failed === 0 ? "Fetched {$ok} product queries." : "Fetched {$ok}, {$failed} failed.", $ok);
        return ['ok' => $ok, 'failed' => $failed, 'blocked' => false];
    }

    /** Download the KEV catalog and replace the local copy. Returns the number of entries, or throws. */
    public function refreshKev(): int
    {
        try {
            $rows = FeedParser::kev($this->http->getJson($this->kevUrl));
            if (count($rows) < 1) {
                throw new \RuntimeException('The KEV catalog was empty; keeping the previous copy.');
            }
            $this->repo->replaceKev($rows);
            $this->repo->feedStatus('kev', true, count($rows) . ' known exploited vulnerabilities.', count($rows));
            return count($rows);
        } catch (\RuntimeException $ex) {
            $this->repo->feedStatus('kev', false, $ex->getMessage());
            throw $ex;
        }
    }

    /** Refresh EPSS scores for CVEs on open services (paced like the public API asks). Returns how many were updated. */
    public function refreshEpss(): int
    {
        $count = 0;
        try {
            foreach (array_chunk($this->repo->matchedCveIds(), self::EPSS_BATCH) as $i => $batch) {
                if ($i > 0) {
                    usleep((int) (($this->nvdDelayOverride ?? 1.0) * 1e6));
                }
                $rows = FeedParser::epss($this->http->getJson($this->epssBase . '/data/v1/epss?' . http_build_query(['cve' => implode(',', $batch)])));
                $this->repo->storeEpss($rows);
                $count += count($rows);
            }
            $this->repo->feedStatus('epss', true, "{$count} scores updated.", $count);
            return $count;
        } catch (\RuntimeException $ex) {
            $this->repo->feedStatus('epss', false, $ex->getMessage());
            throw $ex;
        }
    }

    /**
     * Wait until the NVD rate limit allows another request. The last request
     * time is shared through the database, so the cron job and scan workers
     * together never exceed the limit.
     *
     * @throws RateLimited while NVD has asked us to back off.
     */
    private function nvdPace(): void
    {
        $until = $this->repo->nvdBlockedUntil();
        if ($until > time()) {
            throw new RateLimited('NVD asked us to wait until ' . gmdate('Y-m-d H:i', $until) . ' UTC.', $until - time());
        }
        $delay = $this->nvdDelayOverride ?? ($this->nvdKey !== null ? 0.7 : 6.5);
        $this->repo->withNvdPaceLock(function () use ($delay): void {
            $wait = $this->repo->nvdLastRequest() + $delay - microtime(true);
            if ($wait > 0) {
                usleep((int) (min($wait, 60) * 1e6));
            }
            $this->repo->setNvdLastRequest(microtime(true));
        });
    }
}

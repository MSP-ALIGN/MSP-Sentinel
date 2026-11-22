<?php

declare(strict_types=1);

namespace Sentinel\Vulns;

use PDO;

/**
 * Matches open services to CVEs using cached NVD answers.
 *
 * Rules (from the brief: "never guess"):
 * - nmap reported a product AND version: every CVE NVD lists as affecting
 *   that product at that version is CONFIRMED, meaning "the reported version
 *   is affected". Banners can be wrong, and the UI says so.
 * - The banner shows a Linux distribution build (Ubuntu, Debian, RHEL,
 *   CentOS...): distributions backport fixes without changing the version,
 *   so the same CVEs are marked DISTRO ("check the distribution's notices"),
 *   never confirmed.
 * - Product known, version unknown: only CVEs in the CISA KEV catalog are
 *   recorded, as POSSIBLE. The whole product history is never listed as if it applied.
 * - No usable CPE: nothing is matched.
 * - If the product or version changed and the new answer isn't available
 *   yet, the old matches are removed. They described a different version.
 *
 * Security assumptions: CPE strings from banners are validated by Cpe::parse.
 * Fetching (when allowed) is capped by count AND by wall-clock time, and stops
 * at the first rate-limit answer, so a scan job can't stall on NVD.
 */
final class VulnMatcher
{
    /** Banner markers of distribution builds, which often carry backported fixes. */
    private const DISTRO_MARKERS = '/\b(ubuntu|debian|deb\d+u\d+|el\d+|centos|rhel|red ?hat|rocky|alma(linux)?|suse|sles|amzn|amazon linux|fedora|raspbian)\b|~deb\d|\+deb\d/i';

    /** Uses the repository for data and (optionally) the updater to fetch missing answers. */
    public function __construct(private readonly PDO $db, private readonly VulnRepository $repo, private readonly ?FeedUpdater $updater = null)
    {
    }

    /**
     * Match the open services of one client (or all clients when $clientId is null).
     *
     * @param int        $fetchBudget  How many NVD queries may be fetched now. The rest stay pending for the feeds job.
     * @param float|null $timeBudget   Stop fetching after this many seconds (matching from cache continues).
     * @return array{services:int, matches:int, pending:int}
     */
    public function matchClient(?int $clientId, int $fetchBudget = 0, ?float $timeBudget = null): array
    {
        $started = microtime(true);
        $sql = "SELECT s.id, s.cpe, s.product, s.version, s.extra_info FROM services s JOIN assets a ON a.id = s.asset_id WHERE s.is_open = 1"
            . ($clientId === null ? '' : ' AND a.client_id = :c');
        $stmt = $this->db->prepare($sql);
        $stmt->execute($clientId === null ? [] : ['c' => $clientId]);
        $stats = ['services' => 0, 'matches' => 0, 'pending' => 0];
        $mayFetch = $this->updater !== null && !$this->updater->nvdBlocked();
        foreach ($stmt->fetchAll() as $svc) {
            $stats['services']++;
            $cpe = Cpe::parse((string) $svc['cpe']);
            if ($cpe === null) {
                $this->repo->setServiceMatches((int) $svc['id'], '', []);
                continue;
            }
            $queries = Cpe::matchStrings($cpe);
            $fetched = [];
            foreach ($queries as $query) {
                $this->repo->ensureQuery($query);
                $status = $this->repo->query($query);
                $withinTime = $timeBudget === null || microtime(true) - $started < $timeBudget;
                if (($status['fetched_at'] ?? null) === null && $mayFetch && $fetchBudget > 0 && $withinTime) {
                    $fetchBudget--;
                    try {
                        $this->updater->fetchQuery($query);
                    } catch (RateLimited) {
                        $mayFetch = false; // NVD said stop: no more fetching in this run
                    }
                    $status = $this->repo->query($query);
                }
                if (($status['fetched_at'] ?? null) !== null) {
                    $fetched[] = $query;
                }
            }
            $primary = $queries[0];
            if ($fetched === []) {
                $stats['pending']++;
                // Keep earlier matches only if they were for this same product and version.
                $this->repo->clearServiceMatchesUnless((int) $svc['id'], $queries);
                continue;
            }
            $cves = [];
            foreach ($fetched as $query) {
                foreach ($this->repo->cvesForQuery($query) as $id) {
                    $cves[$id] = true;
                }
            }
            $cves = array_keys($cves);
            $matches = [];
            if ($cpe['version'] !== '') {
                $distro = preg_match(self::DISTRO_MARKERS, $svc['product'] . ' ' . $svc['version'] . ' ' . $svc['extra_info']) === 1;
                foreach ($cves as $id) {
                    $matches[$id] = $distro ? 'distro' : 'confirmed';
                }
            } else {
                foreach ($this->repo->kevSubset($cves) as $id) {
                    $matches[$id] = 'possible';
                }
            }
            $this->repo->setServiceMatches((int) $svc['id'], $primary, $matches);
            $stats['matches'] += count($matches);
        }
        return $stats;
    }

    /**
     * Match detected website components (CMS, JavaScript libraries) of one client or all clients.
     * Same rules as services: a known version gives "confirmed" matches; without a version only
     * known-exploited CVEs are kept, as "possible". Data not fetched yet stays pending for the feeds job.
     *
     * @return array{components:int, matches:int, pending:int}
     */
    public function matchComponents(\Sentinel\Web\WebsiteRepository $store, ?int $clientId, int $fetchBudget = 0): array
    {
        $stats = ['components' => 0, 'matches' => 0, 'pending' => 0];
        $mayFetch = $this->updater !== null && !$this->updater->nvdBlocked();
        foreach ($store->componentsToMatch($clientId) as $comp) {
            $stats['components']++;
            $cpe = Cpe::parse($comp['cpe']);
            if ($cpe === null) {
                $store->setComponentMatches($comp['id'], '', []);
                continue;
            }
            $queries = Cpe::matchStrings($cpe);
            $fetched = [];
            foreach ($queries as $query) {
                $this->repo->ensureQuery($query);
                $status = $this->repo->query($query);
                if (($status['fetched_at'] ?? null) === null && $mayFetch && $fetchBudget > 0) {
                    $fetchBudget--;
                    try {
                        $this->updater->fetchQuery($query);
                    } catch (RateLimited) {
                        $mayFetch = false;
                    }
                    $status = $this->repo->query($query);
                }
                if (($status['fetched_at'] ?? null) !== null) {
                    $fetched[] = $query;
                }
            }
            if ($fetched === []) {
                $stats['pending']++;
                // Keep earlier matches for this same product and version until the data arrives, but drop
                // matches of an earlier version: they would claim CVEs for a version no longer on the page.
                $store->clearComponentMatchesUnless($comp['id'], $queries[0]);
                continue;
            }
            $cves = [];
            foreach ($fetched as $query) {
                foreach ($this->repo->cvesForQuery($query) as $id) {
                    $cves[$id] = true;
                }
            }
            $matches = [];
            foreach ($cpe['version'] !== '' ? array_keys($cves) : $this->repo->kevSubset(array_keys($cves)) as $id) {
                $matches[$id] = $cpe['version'] !== '' ? 'confirmed' : 'possible';
            }
            $store->setComponentMatches($comp['id'], $queries[0], $matches);
            $stats['matches'] += count($matches);
        }
        return $stats;
    }
}

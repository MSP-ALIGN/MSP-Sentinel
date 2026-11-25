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
 * - A CVE NVD limits to some platforms (e.g. Chrome "running on" Android, 1.49): for installed software only
 *   devices on that platform get it (unknown OS: possible); for network services and websites, whose OS is not
 *   known, it is possible, never confirmed.
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
        // Demo clients (made-up data) keep their example matches: never re-matched, never looked up.
        $sql = "SELECT s.id, s.cpe, s.product, s.version, s.extra_info FROM services s JOIN assets a ON a.id = s.asset_id
                JOIN clients c ON c.id = a.client_id AND c.is_demo = 0 WHERE s.is_open = 1"
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
            $limited = $this->platformLimits($fetched);
            $cves = array_keys($cves);
            $matches = [];
            if ($cpe['version'] !== '') {
                $distro = preg_match(self::DISTRO_MARKERS, $svc['product'] . ' ' . $svc['version'] . ' ' . $svc['extra_info']) === 1;
                foreach ($cves as $id) {
                    // Limited to some platforms (1.49): the service's OS isn't known, so never confirmed.
                    $matches[$id] = isset($limited[$id]) ? 'possible' : ($distro ? 'distro' : 'confirmed');
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
     * Match detected website components (CMS, JavaScript libraries) with a known product.
     *
     * @return array{components:int, matches:int, pending:int}
     */
    public function matchComponents(\Sentinel\Web\WebsiteRepository $store, ?int $clientId, int $fetchBudget = 0): array
    {
        $stats = ['components' => 0, 'matches' => 0, 'pending' => 0];
        $mayFetch = $this->updater !== null && !$this->updater->nvdBlocked();
        foreach ($store->componentsToMatch($clientId) as $comp) {
            $stats['components']++;
            $result = $this->matchesForCpe($comp['cpe'], $fetchBudget, $mayFetch);
            if ($result === false) {
                $store->setComponentMatches($comp['id'], '', []);
                continue;
            }
            if ($result === null) {
                $stats['pending']++;
                // Keep earlier matches for this same product and version until the data arrives, but drop
                // matches of an earlier version: they would claim CVEs for a version no longer on the page.
                $cpe = Cpe::parse($comp['cpe']);
                $store->clearComponentMatchesUnless($comp['id'], $cpe === null ? '' : Cpe::matchStrings($cpe)[0]);
                continue;
            }
            // Website components: the server's OS isn't known, so platform-limited CVEs are possible only (1.49).
            foreach (array_keys($result['platforms']) as $id) {
                $result['matches'][$id] = 'possible';
            }
            $store->setComponentMatches($comp['id'], $result['query'], $result['matches']);
            $stats['matches'] += count($result['matches']);
        }
        return $stats;
    }

    /**
     * Match installed software on internal devices (inventory sources), once per distinct product version.
     * Same rules: a known version gives confirmed matches; data still missing leaves earlier matches alone.
     *
     * @return array{products:int, matches:int, pending:int}
     */
    public function matchSoftware(\Sentinel\Inventory\InventoryRepository $store, ?int $clientId, int $fetchBudget = 0): array
    {
        $stats = ['products' => 0, 'matches' => 0, 'pending' => 0];
        $mayFetch = $this->updater !== null && !$this->updater->nvdBlocked();
        foreach ($store->cpesToMatch($clientId) as $cpe) {
            $stats['products']++;
            $result = $this->matchesForCpe($cpe, $fetchBudget, $mayFetch);
            if ($result === false) {
                $store->setMatchesForCpe($clientId, $cpe, [], '');
                continue;
            }
            if ($result === null) {
                $stats['pending']++;
                $store->markPending($clientId, $cpe); // the device's findings wait for this data instead of resolving
                continue;
            }
            $store->setMatchesForCpe($clientId, $cpe, $result['matches'], $result['query'], $result['platforms']);
            $stats['matches'] += count($result['matches']);
        }
        return $stats;
    }

    /**
     * CVE matches for one CPE (2.2 form, with or without version), fetching NVD data within the budget.
     *
     * @return array{query:string, matches:array<string,string>}|null|false null while data is pending;
     *         false when the CPE can't be parsed.
     */
    private function matchesForCpe(string $uri, int &$fetchBudget, bool &$mayFetch): array|null|false
    {
        $cpe = Cpe::parse($uri);
        if ($cpe === null) {
            return false;
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
            return null;
        }
        $cves = [];
        foreach ($fetched as $query) {
            foreach ($this->repo->cvesForQuery($query) as $id) {
                $cves[$id] = true;
            }
        }
        $platforms = $this->platformLimits($fetched);
        $matches = [];
        foreach ($cpe['version'] !== '' ? array_keys($cves) : $this->repo->kevSubset(array_keys($cves)) as $id) {
            $matches[$id] = $cpe['version'] !== '' ? 'confirmed' : 'possible';
        }
        return ['query' => $queries[0], 'matches' => $matches, 'platforms' => array_intersect_key($platforms, $matches)];
    }

    /**
     * Platform limits over several NVD answers for one product (1.49.1): a CVE counts as limited only if EVERY answer
     * that lists it limits it (any unlimited listing wins), and then to the union of the platforms named.
     *
     * @param list<string> $queries
     * @return array<string,list<string>>
     */
    private function platformLimits(array $queries): array
    {
        $listed = [];
        $limits = [];
        foreach ($queries as $query) {
            $limited = $this->repo->platformsForQuery($query);
            foreach ($this->repo->cvesForQuery($query) as $id) {
                $listed[$id] = ($listed[$id] ?? true) && isset($limited[$id]);
                if (isset($limited[$id])) {
                    $limits[$id] = array_values(array_unique(array_merge($limits[$id] ?? [], $limited[$id])));
                }
            }
        }
        return array_intersect_key($limits, array_filter($listed));
    }
}

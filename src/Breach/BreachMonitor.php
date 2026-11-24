<?php

declare(strict_types=1);

namespace Sentinel\Breach;

use PDO;
use Sentinel\Core\Audit;
use Sentinel\Core\Settings;
use Sentinel\Scope\AuthorisationRepository;
use Sentinel\Scope\ScopeService;

/**
 * Breach monitoring (1.33): once a week, reads XposedOrNot's breach data for the domains the MSP verified there, and
 * gives each client the breached addresses of ITS domains: a domain counts for a client when it is in the client's
 * active "authorised to scan" register (exactly, or under a "*." entry). Domains in no client's register are listed
 * for the admin and otherwise ignored. Addresses are stored in breach_exposures with each breach's name, date and
 * what was exposed (never a password or hash); the findings refresh turns them into findings (FindingsEngine): a
 * breach in the last 12 months is a Fail, older ones a Warning, one finding per address.
 *
 * Archived and demo clients are skipped. An address the provider no longer lists (or whose domain left the client's
 * register) is removed after a successful read, so its finding resolves. A failed read changes nothing.
 *
 * Untrusted: everything from XposedOrNot (validated in XonClient). Security assumptions: the API key is a secret
 * setting (encrypted, never shown or logged); addresses are personal data, shown only to signed-in users and never
 * logged; runs are serialised with a database lock.
 */
final class BreachMonitor
{
    /** Days between automatic checks. */
    public const INTERVAL_DAYS = 7;

    /** @param \Closure():array<string,mixed> $refresh refreshes one client's findings (FindingsEngine::refreshClient) */
    public function __construct(private readonly PDO $db, private readonly Settings $settings, private readonly Audit $audit,
        private readonly AuthorisationRepository $authorisations, private readonly ?XonClient $xon, private readonly ?\Closure $refresh = null)
    {
    }

    /** Run when due (worker). Returns the summary, or null when nothing ran. */
    public function runIfDue(): ?string
    {
        if ($this->xon === null || $this->settings->fresh('breach_enabled') !== '1') {
            return null;
        }
        $last = $this->settings->fresh('breach_last_run');
        if ($last !== '' && strtotime($last . ' UTC') > time() - self::INTERVAL_DAYS * 86400) {
            return null;
        }
        return $this->run();
    }

    /** One check now (worker when due, or an admin's "Check now"). Returns a summary for the admin. */
    public function run(): string
    {
        if ($this->xon === null) {
            return 'Breach monitoring is not set up.';
        }
        $lock = $this->db->quote('msp_sentinel_breach_' . substr(hash('sha256', (string) $this->db->query('SELECT DATABASE()')->fetchColumn()), 0, 16));
        if ((int) $this->db->query("SELECT GET_LOCK({$lock}, 0)")->fetchColumn() !== 1) {
            return 'Another breach check is running.';
        }
        try {
            $this->settings->set('breach_last_run', gmdate('Y-m-d H:i:s'));
            try {
                $data = $this->xon->domainBreaches();
            } catch (XonException $ex) {
                $summary = 'Stopped: ' . $ex->getMessage();
                $this->settings->set('breach_last_result', $summary);
                $this->settings->set('breach_last_ok', '0');
                return $summary;
            }
            $byDomain = [];
            foreach ($data['exposures'] as $e) {
                $byDomain[$e['domain']][$e['email']][$e['breach']] = true;
            }
            $verified = array_values(array_unique(array_merge($data['domains'], array_keys($byDomain))));
            $clients = $this->db->query('SELECT id, timezone FROM clients WHERE is_archived = 0 AND is_demo = 0')->fetchAll();
            $matched = [];
            $addresses = 0;
            $touched = [];
            foreach ($clients as $c) {
                $cid = (int) $c['id'];
                $entries = array_values(array_filter($this->authorisations->activeEntries($cid, ScopeService::today((string) $c['timezone'])),
                    static fn (array $e): bool => $e['entry_type'] === 'domain'));
                $keep = [];
                foreach ($verified as $domain) {
                    if (!ScopeService::matches($entries, $domain)) {
                        continue;
                    }
                    $matched[$domain] = true;
                    foreach ($byDomain[$domain] ?? [] as $email => $names) {
                        $list = [];
                        foreach (array_keys($names) as $name) {
                            $info = $data['breaches'][$name] ?? ['date' => '', 'data' => []];
                            $list[] = ['name' => $name, 'date' => $info['date'], 'data' => $info['data']];
                        }
                        usort($list, static fn (array $a, array $b): int => strcmp($b['date'], $a['date'])); // newest first
                        $this->db->prepare('INSERT INTO breach_exposures (client_id, email, domain, breaches, first_seen, last_seen)
                                            VALUES (:c, :e, :d, :b, UTC_TIMESTAMP(), UTC_TIMESTAMP())
                                            ON DUPLICATE KEY UPDATE domain = VALUES(domain), breaches = VALUES(breaches), last_seen = UTC_TIMESTAMP()')
                            ->execute(['c' => $cid, 'e' => $email, 'd' => $domain, 'b' => json_encode(array_slice($list, 0, 200))]);
                        $keep[] = $email;
                        $addresses++;
                    }
                }
                // Addresses no longer listed (or whose domain left the register): removed, so their findings resolve.
                if ($keep === []) {
                    $del = $this->db->prepare('DELETE FROM breach_exposures WHERE client_id = :c');
                    $del->execute(['c' => $cid]);
                } else {
                    $del = $this->db->prepare('DELETE FROM breach_exposures WHERE client_id = ? AND email NOT IN (' . implode(',', array_fill(0, count($keep), '?')) . ')');
                    $del->execute(array_merge([$cid], $keep));
                }
                if ($keep !== [] || $del->rowCount() > 0) {
                    $touched[] = $cid;
                }
            }
            foreach ($touched as $cid) {
                try {
                    $this->refresh?->__invoke($cid);
                } catch (\Throwable $ex) {
                    error_log('[msp-sentinel] breach findings refresh failed for client ' . $cid . ': ' . $ex->getMessage());
                }
            }
            $unmatched = array_values(array_diff($verified, array_keys($matched)));
            sort($unmatched);
            $this->settings->set('breach_unmatched', implode(',', array_slice($unmatched, 0, 100)));
            $summary = sprintf('%d verified domain(s), %d in clients\' registers; %d breached address(es) for %d client(s).',
                count($verified), count($matched), $addresses, count(array_unique($touched)));
            $this->settings->set('breach_last_result', $summary);
            $this->settings->set('breach_last_ok', '1');
            $this->audit->log('breach.checked', null, 'breach-monitor', null, null, ['domains' => count($verified), 'addresses' => $addresses]);
            return $summary;
        } finally {
            $this->db->query("SELECT RELEASE_LOCK({$lock})");
        }
    }

    /**
     * A client's breached addresses, newest breach first.
     *
     * @return list<array{email:string, domain:string, breaches:list<array{name:string, date:string, data:list<string>}>, first_seen:string, last_seen:string}>
     */
    public static function forClient(PDO $db, int $clientId): array
    {
        $stmt = $db->prepare('SELECT email, domain, breaches, first_seen, last_seen FROM breach_exposures WHERE client_id = :c ORDER BY email');
        $stmt->execute(['c' => $clientId]);
        $out = [];
        foreach ($stmt->fetchAll() as $r) {
            $out[] = ['email' => (string) $r['email'], 'domain' => (string) $r['domain'], 'breaches' => (array) (json_decode((string) $r['breaches'], true) ?: []),
                'first_seen' => (string) $r['first_seen'], 'last_seen' => (string) $r['last_seen']];
        }
        usort($out, static fn (array $a, array $b): int => strcmp((string) ($b['breaches'][0]['date'] ?? ''), (string) ($a['breaches'][0]['date'] ?? '')));
        return $out;
    }

    /** Whether a breach date (Y-m-d) is within the last 12 months: such a breach is a Fail. */
    public static function recent(string $date): bool
    {
        return $date !== '' && $date >= gmdate('Y-m-d', strtotime('-12 months'));
    }
}

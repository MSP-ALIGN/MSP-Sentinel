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
 * Archived and demo clients are skipped (archived clients' rows are removed). A client without an active
 * authorisation is left as it is (not checked is not fixed). An address of a domain the answer covers that it no
 * longer lists, or whose domain left the client's register, is removed after a successful read, so its finding
 * resolves; but an answer that would remove more than half of what is known (or covers no domain at all) removes
 * nothing and says so (an outage or a lapsed verification is likelier than a mass clean-up). A failed read changes
 * nothing and is retried RETRY_HOURS later.
 *
 * Untrusted: everything from XposedOrNot (validated in XonClient). Security assumptions: the API key is a secret
 * setting (encrypted, never shown or logged); addresses are personal data: full addresses only on the client page for
 * technicians and admins and in the finding's detail; titles, targets (so alerts, chat webhooks and lists) carry the
 * masked form (j***@client.example); never logged. Runs are serialised with a database lock.
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

    /** Hours before an automatic check is tried again after one that failed. */
    public const RETRY_HOURS = 6;
    /** Above this share of stored addresses disappearing in one answer, nothing is removed (an incomplete answer). */
    public const MAX_DROP_SHARE = 0.5;

    /**
     * Run when due (worker): a week after the last successful check, and after a failed one RETRY_HOURS later.
     * Returns the summary, or null when nothing ran.
     */
    public function runIfDue(): ?string
    {
        if ($this->xon === null || $this->settings->fresh('breach_enabled') !== '1') {
            return null;
        }
        $lastOk = $this->settings->fresh('breach_last_ok_run');
        $lastTry = $this->settings->fresh('breach_last_run');
        if ($lastOk !== '' && strtotime($lastOk . ' UTC') > time() - self::INTERVAL_DAYS * 86400) {
            return null;
        }
        if ($lastTry !== '' && strtotime($lastTry . ' UTC') > time() - self::RETRY_HOURS * 3600) {
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
                return $this->stopped($ex->getMessage());
            }
            $byDomain = [];
            foreach ($data['exposures'] as $e) {
                $byDomain[$e['domain']][$e['email']][$e['breach']] = true;
            }
            // The domains this answer speaks for: only their addresses can be judged "no longer listed".
            $verified = array_values(array_unique(array_merge($data['domains'], array_keys($byDomain))));
            $stored = (int) $this->db->query('SELECT COUNT(*) FROM breach_exposures')->fetchColumn();
            // Archived clients keep no breach data (personal data with no use).
            $this->db->exec('DELETE b FROM breach_exposures b JOIN clients c ON c.id = b.client_id WHERE c.is_archived = 1');
            $clients = $this->db->query('SELECT id, timezone FROM clients WHERE is_archived = 0 AND is_demo = 0')->fetchAll();
            // Plan first, write after the guard: per client, the rows to write and the ones to remove.
            $plans = [];
            $matched = [];
            $drops = 0;
            foreach ($clients as $c) {
                $cid = (int) $c['id'];
                $entries = array_values(array_filter($this->authorisations->activeEntries($cid, ScopeService::today((string) $c['timezone'])),
                    static fn (array $e): bool => $e['entry_type'] === 'domain'));
                if ($entries === []) {
                    continue; // no active authorisation (expired, or none): left as it is; not checked is not fixed
                }
                $rows = [];
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
                        usort($list, static fn (array $a, array $b): int => [$b['date'], $a['name']] <=> [$a['date'], $b['name']]); // newest first, then by name
                        $rows[$email] = ['domain' => $domain, 'breaches' => array_slice($list, 0, 200)];
                    }
                }
                // Removed: addresses of domains this answer covers that it no longer lists, and addresses of domains no
                // longer in the client's (active) register.
                $remove = [];
                $cur = $this->db->prepare('SELECT email, domain FROM breach_exposures WHERE client_id = :c');
                $cur->execute(['c' => $cid]);
                foreach ($cur->fetchAll() as $old) {
                    $covered = in_array((string) $old['domain'], $verified, true);
                    $inRegister = ScopeService::matches($entries, (string) $old['domain']);
                    if (!isset($rows[$old['email']]) && (($covered && $inRegister) || !$inRegister)) {
                        $remove[] = (string) $old['email'];
                    }
                }
                $drops += count($remove);
                $plans[$cid] = ['rows' => $rows, 'remove' => $remove];
            }
            // An answer that would remove most of what is known is more likely incomplete than a mass clean-up.
            $guard = $stored > 0 && ($verified === [] || $drops > $stored * self::MAX_DROP_SHARE);
            $addresses = 0;
            $touched = [];
            foreach ($plans as $cid => $plan) {
                $this->db->beginTransaction();
                try {
                    foreach ($plan['rows'] as $email => $row) {
                        $this->db->prepare('INSERT INTO breach_exposures (client_id, email, domain, breaches, first_seen, last_seen)
                                            VALUES (:c, :e, :d, :b, UTC_TIMESTAMP(), UTC_TIMESTAMP())
                                            ON DUPLICATE KEY UPDATE domain = VALUES(domain), breaches = VALUES(breaches), last_seen = UTC_TIMESTAMP()')
                            ->execute(['c' => $cid, 'e' => (string) $email, 'd' => $row['domain'], 'b' => json_encode($row['breaches'])]);
                        $addresses++;
                    }
                    if (!$guard && $plan['remove'] !== []) {
                        $del = $this->db->prepare('DELETE FROM breach_exposures WHERE client_id = ? AND email IN (' . implode(',', array_fill(0, count($plan['remove']), '?')) . ')');
                        $del->execute(array_merge([$cid], $plan['remove']));
                    }
                    $this->db->commit();
                } catch (\Throwable $ex) {
                    $this->db->rollBack();
                    error_log('[msp-sentinel] breach monitoring: storing client ' . $cid . ' failed: ' . $ex->getMessage());
                    return $this->stopped('the results could not be stored (see the PHP error log).');
                }
                if ($plan['rows'] !== [] || (!$guard && $plan['remove'] !== [])) {
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
                count($verified), count($matched), $addresses, count($touched))
                . ($guard ? ' ' . sprintf('Nothing was removed: this answer would have removed %d of %d known address(es), which looks incomplete (check the verified domains in XposedOrNot).', $drops, $stored) : '');
            $this->settings->set('breach_last_result', $summary);
            $this->settings->set('breach_last_ok', $guard ? '0' : '1');
            $this->settings->set('breach_last_ok_run', gmdate('Y-m-d H:i:s'));
            $this->audit->log('breach.checked', null, 'breach-monitor', null, null, ['domains' => count($verified), 'addresses' => $addresses, 'removal_held' => $guard]);
            return $summary;
        } finally {
            $this->db->query("SELECT RELEASE_LOCK({$lock})");
        }
    }

    /** Record a check that stopped (nothing changed); tried again RETRY_HOURS later. */
    private function stopped(string $why): string
    {
        $summary = 'Stopped: ' . $why;
        $this->settings->set('breach_last_result', $summary);
        $this->settings->set('breach_last_ok', '0');
        return $summary;
    }

    /** An address for titles, alerts and chat: the first character and the domain (j***@client.example). */
    public static function masked(string $email): string
    {
        $at = strrpos($email, '@');
        return $at === false ? '***' : mb_substr($email, 0, 1) . '***' . substr($email, $at);
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

    /**
     * Whether a breach date (Y-m-d) is within the last 12 months: such a breach is a Fail. A breach without a date
     * counts as older (Warning): the provider dates nearly all breaches, and an undated one can't be called recent.
     */
    public static function recent(string $date): bool
    {
        return $date !== '' && $date >= gmdate('Y-m-d', strtotime('-12 months'));
    }
}

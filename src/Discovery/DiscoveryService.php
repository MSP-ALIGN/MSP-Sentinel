<?php

declare(strict_types=1);

namespace Sentinel\Discovery;

use PDO;
use Sentinel\Clients\ClientRepository;
use Sentinel\Scope\AuthorisationRepository;
use Sentinel\Scope\ScopeParser;
use Sentinel\Scope\ScopeService;

/**
 * Passive target discovery: finds hostnames and IP addresses a client
 * probably owns but hasn't put in scope yet, and stores them as suggestions
 * for an admin to approve.
 *
 * Sources, starting from the domains and IPs in the client's ACTIVE scope:
 * - DNS: A/AAAA/MX/NS/CNAME of each domain, plus a fixed list of common
 *   names (www, mail, vpn, remote...)
 * - crt.sh: hostnames from public certificates (only names that still resolve are suggested)
 * - reverse DNS (PTR) of in-scope IPs
 *
 * Security assumptions:
 * - Passive only: DNS lookups through the configured resolver and HTTPS to
 *   crt.sh. Nothing connects to client systems. Kill switches are still
 *   honoured: a pause (or losing the active authorisation) stops all
 *   outbound activity, checked at the start, every 25 queries, and before
 *   each crt.sh call and the reverse-DNS step.
 * - DNS answers are followed as a chain from the question name. Records for
 *   other names are ignored, and every name is canonicalised before use.
 * - Only hostnames UNDER the client's own scope domains are suggested.
 *   Names elsewhere (hosted mail, DNS providers, CDNs) are listed for
 *   information only. IPs reached through an alias at another provider are
 *   flagged as possibly third-party.
 * - Every suggested value passes the same validation as typed scope entries
 *   (public, not reserved). A suggestion grants nothing until an admin
 *   records an authorisation.
 * - One run per client at a time (database lock), with a time budget for manual runs.
 */
final class DiscoveryService
{
    /** Common hostnames worth checking under each scope domain. */
    public const COMMON_NAMES = [
        'www', 'mail', 'webmail', 'smtp', 'imap', 'mx', 'autodiscover', 'owa', 'exchange', 'vpn', 'sslvpn', 'remote',
        'rdweb', 'rds', 'gateway', 'portal', 'citrix', 'firewall', 'fw', 'extranet', 'intranet', 'ftp', 'sftp', 'files',
        'cloud', 'nas', 'api', 'app', 'dev', 'test', 'staging', 'admin', 'cpanel', 'shop', 'helpdesk', 'support', 'ns1', 'ns2',
    ];
    private const MAX_PTR = 64;
    private const MAX_CRT_RESOLVE = 200;
    private const MAX_QUERIES = 5000;
    private const MAX_EXTERNAL = 50;
    private const MAX_ERRORS = 20;

    private float $started = 0.0;
    private ?float $budget = null;
    private int $queries = 0;
    private int $clientId = 0;
    /** @var list<string> */
    private array $seedDomains = [];
    /** @var list<array<string,mixed>> */
    private array $entries = [];
    /** @var array<string,mixed> */
    private array $stats = [];

    /** All collaborators are injected so tests can point them at mock servers. */
    public function __construct(
        private readonly PDO $db,
        private readonly ClientRepository $clients,
        private readonly AuthorisationRepository $authorisations,
        private readonly SuggestionRepository $suggestions,
        private readonly ScopeService $scope,
        private readonly ScopeParser $parser,
        private readonly DnsClient $dns,
        private readonly ?CrtShClient $crtsh,
        private readonly float $crtshDelaySeconds = 1.0,
    ) {
    }

    /**
     * Run discovery for one client.
     *
     * @param string     $trigger       'manual' or 'scheduled'.
     * @param float|null $budgetSeconds Time limit (null = no limit, for the weekly CLI job).
     * @return array{status:string, message:string, run_id:?int, new:int}
     *         status: ok | partial | failed | refused (refused = not started, no run recorded).
     */
    public function run(int $clientId, string $trigger, ?int $userId, ?float $budgetSeconds): array
    {
        $client = $this->clients->find($clientId);
        $refuse = static fn (string $m): array => ['status' => 'refused', 'message' => $m, 'run_id' => null, 'new' => 0];
        if ($client === null || (int) $client['is_archived'] === 1) {
            return $refuse(__('Discovery is not available for archived clients.'));
        }
        if ((int) $client['scanning_paused'] === 1 || $this->scope->globallyPaused()) {
            return $refuse(__('Scanning is paused, so discovery is paused too.'));
        }
        $this->entries = $this->authorisations->activeEntries($clientId, ScopeService::today((string) $client['timezone']));
        if ($this->entries === []) {
            return $refuse(__('This client has no active authorisation, so there is nothing to start discovery from.'));
        }
        // Lock names are server-wide in MariaDB, so include the database name: two installs on one server don't block each other.
        $lock = 'msp_sentinel_disc_' . substr(hash('sha256', (string) $this->db->query('SELECT DATABASE()')->fetchColumn()), 0, 16) . '_' . $clientId;
        if ((int) $this->db->query("SELECT GET_LOCK(" . $this->db->quote($lock) . ", 0)")->fetchColumn() !== 1) {
            return $refuse(__('Discovery is already running for this client.'));
        }

        $this->clientId = $clientId;
        $this->started = microtime(true);
        $this->budget = $budgetSeconds;
        $this->queries = 0;
        $this->stats = ['new' => 0, 'seen_again' => 0, 'already_in_scope' => 0, 'non_public_skipped' => 0,
                        'certificate_names_not_resolving' => 0, 'external' => [], 'errors' => [], 'dns_ok' => 0, 'dns_failed' => 0];
        $runId = $this->suggestions->startRun($clientId, $trigger, $userId);
        $status = 'ok';
        $message = '';
        try {
            $this->discover();
            if ($this->stats['errors'] !== []) {
                $status = 'partial';
            }
        } catch (DiscoveryStopped $stop) {
            $status = $stop->failed ? 'failed' : 'partial';
            $message = $stop->getMessage();
            $this->stats['errors'][] = $message;
        } catch (\Throwable $ex) {
            $status = 'failed';
            $message = __('Discovery failed unexpectedly. The details are in the server log.');
            error_log('[msp-sentinel] discovery failed for client ' . $clientId . ': ' . $ex->getMessage());
            $this->stats['errors'][] = $message;
        } finally {
            // Recording the end of the run and releasing the lock must happen even if one of them fails.
            try {
                $this->stats['queries'] = $this->queries;
                $this->stats['seconds'] = round(microtime(true) - $this->started, 1);
                $this->stats['errors'] = array_slice($this->stats['errors'], 0, self::MAX_ERRORS);
                $this->suggestions->finishRun($runId, $status, $this->stats);
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] could not record discovery run ' . $runId . ': ' . $ex->getMessage());
                try {
                    $this->suggestions->finishRun($runId, 'failed', ['errors' => [__('The run summary could not be saved.')]]);
                } catch (\Throwable) {
                    // nothing more we can do; the lock is still released below
                }
                $status = 'failed';
            } finally {
                $this->db->query("SELECT RELEASE_LOCK(" . $this->db->quote($lock) . ")");
            }
        }
        if ($message === '') {
            $message = $status === 'ok'
                ? __('Discovery finished: {n} new suggestion(s).', ['n' => $this->stats['new']])
                : __('Discovery finished with some problems: {n} new suggestion(s). See the last run details.', ['n' => $this->stats['new']]);
        }
        return ['status' => $status, 'message' => $message, 'run_id' => $runId, 'new' => (int) $this->stats['new']];
    }

    /** The discovery steps. */
    private function discover(): void
    {
        $domains = [];
        $ips = [];
        foreach ($this->entries as $e) {
            if ($e['entry_type'] === 'domain') {
                $value = (string) $e['value'];
                $domains[str_starts_with($value, '*.') ? substr($value, 2) : $value] = true;
            } elseif ($e['entry_type'] === 'ip') {
                $ips[(string) $e['value']] = true;
            } elseif ($e['entry_type'] === 'cidr' && $e['range_start'] !== null && strlen((string) $e['range_start']) === 4) {
                // Reverse-lookup small IPv4 ranges only (limited by MAX_PTR overall).
                $start = unpack('N', (string) $e['range_start'])[1];
                $end = unpack('N', (string) $e['range_end'])[1];
                for ($n = $start; $n <= $end && count($ips) < self::MAX_PTR; $n++) {
                    $ips[(string) long2ip($n)] = true;
                }
            }
        }
        $this->seedDomains = array_keys($domains);

        foreach ($this->seedDomains as $domain) {
            $this->checkHost($domain, 'dns', __('address of {host}', ['host' => $domain]), false);
            foreach ([DnsMessage::MX => 'dns-mx', DnsMessage::NS => 'dns-ns'] as $type => $source) {
                foreach ($this->lookup($domain, $type) as $answer) {
                    if ($answer['type'] === $type) {
                        $label = $type === DnsMessage::MX ? __('mail server of {d}', ['d' => $domain]) : __('name server of {d}', ['d' => $domain]);
                        $this->candidateHost($answer['data'], $source, $label, true);
                    }
                }
            }
            foreach (self::COMMON_NAMES as $name) {
                $this->checkHost($name . '.' . $domain, 'dns-common', __('answers DNS'), true);
            }
        }

        // Certificate Transparency: names seen in public certificates, kept only if they still resolve.
        if ($this->crtsh !== null) {
            $resolvedFromCrt = 0;
            foreach ($this->seedDomains as $i => $domain) {
                if ($i > 0 && $this->crtshDelaySeconds > 0) {
                    usleep((int) ($this->crtshDelaySeconds * 1e6)); // be gentle with a free public service
                }
                $this->checkBudget();
                $this->checkStillAllowed();
                try {
                    // Never let one crt.sh call run past the manual time budget.
                    $remainingMs = $this->budget === null ? null : (int) (($this->budget - (microtime(true) - $this->started)) * 1000);
                    $names = $this->crtsh->hostnames($domain, $remainingMs);
                } catch (\RuntimeException $ex) {
                    $this->stats['errors'][] = __('Certificate log lookup for {d} failed: {e}', ['d' => $domain, 'e' => $ex->getMessage()]);
                    continue;
                }
                foreach ($names as $host) {
                    if ($resolvedFromCrt >= self::MAX_CRT_RESOLVE) {
                        $this->stats['errors'][] = __('More certificate names than one run checks ({n}). The rest will be checked next time.', ['n' => self::MAX_CRT_RESOLVE]);
                        break 2;
                    }
                    $resolvedFromCrt++;
                    if (!$this->checkHost($host, 'crtsh', __('seen in public certificate logs'), true)) {
                        $this->stats['certificate_names_not_resolving']++;
                    }
                }
            }
        }

        // Reverse DNS of in-scope addresses. Names found are looked up forwards too, like every other name.
        $this->checkStillAllowed();
        foreach (array_keys($ips) as $ip) {
            $reverse = DnsMessage::reverseName($ip);
            foreach ($this->lookup($reverse, DnsMessage::PTR) as $answer) {
                if ($answer['type'] === DnsMessage::PTR && $answer['name'] === $reverse) {
                    $this->candidateHost($answer['data'], 'ptr', __('reverse DNS of {ip}', ['ip' => $ip]), true);
                }
            }
        }
    }

    /**
     * Resolve a hostname (A and AAAA). If it exists, suggest the hostname
     * (when $suggestHost) and its addresses.
     *
     * @return bool True if the name resolved.
     */
    private function checkHost(string $host, string $source, string $detail, bool $suggestHost): bool
    {
        $host = ScopeService::canonicalTarget($host);
        if ($host === null) {
            return false;
        }
        $addresses = [];
        $externalAlias = null;
        foreach ([DnsMessage::A, DnsMessage::AAAA] as $type) {
            // Follow the answer chain from the question name: only records owned by the
            // name or by a CNAME target in its chain count (ignore unrelated extra records).
            $chain = [$host => true];
            foreach ($this->lookup($host, $type) as $answer) {
                if (!isset($chain[$answer['name']])) {
                    continue;
                }
                if ($answer['type'] === DnsMessage::CNAME) {
                    $target = ScopeService::canonicalTarget($answer['data']);
                    if ($target === null) {
                        continue;
                    }
                    $chain[$target] = true;
                    if (!$this->isOwnName($target)) {
                        $externalAlias = $target;
                    }
                } elseif ($answer['type'] === $type) {
                    $addresses[$answer['data']] = true;
                }
            }
        }
        if ($addresses === []) {
            return false;
        }
        // A name that only points at private or reserved addresses can't be scanned from outside: don't suggest it.
        $public = array_filter(array_keys($addresses), fn (string $ip): bool => !is_string($this->parser->parse($ip)));
        if ($public === []) {
            $this->stats['non_public_skipped']++;
            return true;
        }
        if ($externalAlias !== null) {
            $this->noteExternal($externalAlias, __('alias target of {host}', ['host' => $host]));
        }
        if ($suggestHost) {
            $this->candidateHost($host, $source, $detail, false);
        }
        foreach (array_keys($addresses) as $ip) {
            $ipDetail = __('address of {host}', ['host' => $host]);
            if ($externalAlias !== null) {
                $ipDetail .= ' ' . __('(through an alias at {provider}: probably a third-party service)', ['provider' => $externalAlias]);
            }
            $this->candidate('ip', (string) $ip, 'dns', $ipDetail, $externalAlias !== null);
        }
        return true;
    }

    /** A hostname found somewhere: suggest it if it's under a scope domain, otherwise list it for information. */
    private function candidateHost(string $name, string $source, string $detail, bool $resolveFirst): void
    {
        $host = ScopeService::canonicalTarget($name);
        if ($host === null) {
            return;
        }
        if (!$this->isOwnName($host)) {
            $this->noteExternal($host, $detail);
            return;
        }
        if ($resolveFirst) {
            $this->checkHost($host, $source, $detail, true);
            return;
        }
        $this->candidate('hostname', $host, $source, $detail, false);
    }

    /** Store a suggestion unless it's already in scope or not a valid public target. */
    private function candidate(string $kind, string $value, string $source, string $detail, bool $thirdParty): void
    {
        $value = ScopeService::canonicalTarget($value);
        if ($value === null) {
            return;
        }
        if (ScopeService::matches($this->entries, $value)) {
            $this->stats['already_in_scope']++;
            return;
        }
        if (is_string($this->parser->parse($value))) {
            $this->stats['non_public_skipped']++;
            return;
        }
        $isNew = $this->suggestions->upsert($this->clientId, $kind, $value, $source, $detail, $thirdParty);
        $this->stats[$isNew ? 'new' : 'seen_again']++;
    }

    /** True if $host is a scope domain or a name under one. */
    private function isOwnName(string $host): bool
    {
        foreach ($this->seedDomains as $domain) {
            if ($host === $domain || str_ends_with($host, '.' . $domain)) {
                return true;
            }
        }
        return false;
    }

    /** Remember a name at another provider (shown in the run summary, never suggested). */
    private function noteExternal(string $host, string $why): void
    {
        if (count($this->stats['external']) < self::MAX_EXTERNAL && !isset($this->stats['external'][$host])) {
            $this->stats['external'][$host] = $why;
        }
    }

    /**
     * One DNS query with budget, kill-switch and failure handling.
     *
     * @return list<array{name:string,type:int,ttl:int,data:string}>
     */
    private function lookup(string $name, int $type): array
    {
        $this->checkBudget();
        if (++$this->queries % 25 === 0) {
            $this->checkStillAllowed();
        }
        try {
            $answers = $this->dns->query($name, $type);
            $this->stats['dns_ok']++;
            return $answers;
        } catch (DnsException $ex) {
            $this->stats['dns_failed']++;
            if ($this->stats['dns_ok'] === 0 && $this->stats['dns_failed'] >= 5) {
                throw new DiscoveryStopped(__('The DNS resolver is not answering: {e}', ['e' => $ex->getMessage()]), true);
            }
            if (count($this->stats['errors']) < self::MAX_ERRORS) {
                $this->stats['errors'][] = __('DNS lookup of {name} failed: {e}', ['name' => $name, 'e' => $ex->getMessage()]);
            }
            return [];
        }
    }

    /**
     * Stop if scanning was paused, the client archived, or its last active
     * authorisation revoked or expired since the run started.
     */
    private function checkStillAllowed(): void
    {
        $client = $this->clients->find($this->clientId);
        if ($client === null || (int) $client['scanning_paused'] === 1 || (int) $client['is_archived'] === 1 || $this->scope->globallyPaused()) {
            throw new DiscoveryStopped(__('Stopped because scanning was paused.'), false);
        }
        if ($this->authorisations->activeEntries($this->clientId, ScopeService::today((string) $client['timezone'])) === []) {
            throw new DiscoveryStopped(__('Stopped because the client no longer has an active authorisation.'), false);
        }
    }

    /** Stop when the time budget or the query cap is used up. */
    private function checkBudget(): void
    {
        if ($this->queries >= self::MAX_QUERIES) {
            throw new DiscoveryStopped(__('Stopped after {n} lookups (the limit for one run).', ['n' => self::MAX_QUERIES]), false);
        }
        if ($this->budget !== null && microtime(true) - $this->started > $this->budget) {
            throw new DiscoveryStopped(__('Stopped after {s} seconds. The weekly run has no time limit and will finish the job.', ['s' => (int) $this->budget]), false);
        }
    }
}

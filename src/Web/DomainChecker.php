<?php

declare(strict_types=1);

namespace Sentinel\Web;

use Sentinel\Discovery\DnsClient;
use Sentinel\Discovery\DnsException;
use Sentinel\Discovery\DnsMessage;
use Sentinel\Scanning\Connector;
use Sentinel\Scanning\HttpProbe;
use Sentinel\Scope\ScopeParser;
use Sentinel\Scope\ScopeService;

/**
 * DNS checks of a client's authorised names (1.28):
 *
 * - Zone transfer: one AXFR request to each nameserver listed for an authorised domain (at most 4 nameservers, 2
 *   addresses each), even when a provider runs it: a nameserver that hands out the whole zone lets anyone list every
 *   name (internal, test and forgotten systems). Only the answer's first messages are read (names and types; at most
 *   ten messages, 5 seconds, 1 MB): enough to prove it is open and show a few names.
 * - Subdomain takeover: a name whose CNAME points at a cloud service (known list below) that no longer exists, so
 *   anyone could claim it and serve content on the client's name. Dangling (the target no longer resolves), or the
 *   provider's own "no such site" page on ONE request to the client's name (Host header) at the address it resolves to.
 *
 * Both run only for names in the client's authorised scope (the caller checks). The nameservers and cloud addresses
 * are usually third parties: each gets one standard request (the owner agreed to that for these checks). Only public
 * addresses are ever contacted: a nameserver or cloud name that resolves to a private, loopback, link-local or other
 * reserved address (perhaps the MSP's own network) is skipped (ScopeParser's rules, as for scope entries).
 * Only providers where an unclaimed or dangling name can really be registered by someone else are listed, so a deleted
 * load balancer or database name (which nobody else can claim) is never reported.
 *
 * Untrusted: every DNS answer and web page (parsed strictly, length-limited, shown escaped).
 */
final class DomainChecker
{
    private const TIMEOUT = 5.0;
    private const MAX_AXFR_BYTES = 1_048_576;

    /**
     * Cloud services whose unclaimed names can be taken over: pattern for the CNAME target => [provider, text of its
     * "no such site" page (null: none checked), whether a target that no longer resolves counts (true only where the
     * name itself can be registered again by anyone: Azure, Elastic Beanstalk and Heroku names; the others always
     * resolve, so only their page tells)].
     */
    public const PROVIDERS = [
        '/\.s3(-website)?[.-]([a-z0-9-]+\.)?amazonaws\.com$/' => ['Amazon S3', 'NoSuchBucket', false],
        '/\.github\.io$/' => ['GitHub Pages', "There isn't a GitHub Pages site here", false],
        '/\.herokuapp\.com$/' => ['Heroku', 'No such app', true],
        '/\.herokudns\.com$/' => ['Heroku', 'No such app', true],
        '/\.azurewebsites\.net$/' => ['Azure App Service', null, true],
        '/\.cloudapp\.net$/' => ['Azure Cloud Services', null, true],
        '/\.cloudapp\.azure\.com$/' => ['Azure virtual machine', null, true],
        '/\.trafficmanager\.net$/' => ['Azure Traffic Manager', null, true],
        '/\.blob\.core\.windows\.net$/' => ['Azure Storage', null, true],
        '/\.azureedge\.net$/' => ['Azure CDN', null, true],
        '/\.elasticbeanstalk\.com$/' => ['AWS Elastic Beanstalk', null, true],
        '/\.myshopify\.com$/' => ['Shopify', 'Sorry, this shop is currently unavailable', false],
        '/\.ghost\.io$/' => ['Ghost', 'The thing you were looking for is no longer here', false],
        '/\.zendesk\.com$/' => ['Zendesk', 'Help Center Closed', false],
        '/\.pantheonsite\.io$/' => ['Pantheon', 'The gods are wise', false],
        '/\.fastly\.net$/' => ['Fastly', 'Fastly error: unknown domain', false],
        '/\.surge\.sh$/' => ['Surge', 'project not found', false],
        '/\.readthedocs\.io$/' => ['Read the Docs', 'unknown to Read the Docs', false],
    ];

    public function __construct(private readonly DnsClient $dns, private readonly Connector $connector, private readonly HttpProbe $http,
        private readonly ScopeParser $addresses)
    {
    }

    /** Whether $ip may be contacted: a public address (the scope rules; documentation ranges only in the test suite). */
    private function publicAddress(string $ip): bool
    {
        $p = $this->addresses->parse($ip);
        return is_array($p) && $p['type'] === 'ip';
    }

    /**
     * Ask each nameserver of $domain for a zone transfer.
     *
     * @return array{domain:string, error:string, nameservers:list<array{ns:string, ip:string, status:string, records:int, sample:list<string>}>}
     *         status: 'open' (it handed out records), 'refused', 'error' (no answer or unusable)
     */
    public function zoneTransfer(string $domain): array
    {
        $out = ['domain' => $domain, 'error' => '', 'nameservers' => []];
        try {
            $ns = array_values(array_unique(array_map(static fn (array $a): string => strtolower(rtrim($a['data'], '.')),
                array_filter($this->dns->query($domain, DnsMessage::NS), static fn (array $a): bool => $a['type'] === DnsMessage::NS))));
        } catch (DnsException $ex) {
            return ['error' => mb_substr($ex->getMessage(), 0, 200)] + $out;
        }
        foreach (array_slice($ns, 0, 4) as $name) {
            if (ScopeService::canonicalTarget($name) !== $name) {
                continue;
            }
            $ips = [];
            foreach ([DnsMessage::A, DnsMessage::AAAA] as $type) {
                try {
                    foreach ($this->dns->query($name, $type) as $a) {
                        if ($a['type'] === $type && filter_var($a['data'], FILTER_VALIDATE_IP) !== false && $this->publicAddress($a['data'])) {
                            $ips[] = $a['data'];
                        }
                    }
                } catch (DnsException) {
                    // no address of this type
                }
            }
            foreach (array_slice(array_values(array_unique($ips)), 0, 2) as $ip) {
                $out['nameservers'][] = ['ns' => $name, 'ip' => $ip] + $this->axfr($ip, $domain);
            }
        }
        return $out;
    }

    /**
     * One AXFR request over TCP. @return array{status:string, records:int, sample:list<string>}
     */
    private function axfr(string $ip, string $domain): array
    {
        $fail = ['status' => 'error', 'records' => 0, 'sample' => []];
        try {
            [$host, $port] = $this->connector->endpoint($ip, 53);
        } catch (\RuntimeException) {
            return $fail;
        }
        $sock = @stream_socket_client('tcp://' . Connector::hostPort($host, $port), $errno, $errstr, self::TIMEOUT);
        if ($sock === false) {
            return $fail;
        }
        stream_set_timeout($sock, (int) self::TIMEOUT);
        // Exactly $n bytes (TCP may split a message anywhere), or less at the deadline or end of stream.
        $readN = static function (int $n, float $deadline) use ($sock): string {
            $buf = '';
            while (strlen($buf) < $n && !feof($sock) && microtime(true) < $deadline) {
                $chunk = fread($sock, $n - strlen($buf));
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $buf .= $chunk;
            }
            return $buf;
        };
        $id = random_int(0, 0xffff);
        $q = DnsMessage::buildAxfr($id, $domain);
        fwrite($sock, pack('n', strlen($q)) . $q);
        $records = 0;
        $data = 0; // records other than SOA: proof the zone itself was handed out
        $sample = [];
        $status = 'error';
        $read = 0;
        $deadline = microtime(true) + self::TIMEOUT;
        try {
            for ($m = 0; $m < 10 && microtime(true) < $deadline && $read < self::MAX_AXFR_BYTES; $m++) {
                $lenBytes = $readN(2, $deadline);
                if (strlen($lenBytes) !== 2) {
                    break;
                }
                $len = unpack('n', $lenBytes)[1];
                $msg = $readN($len, $deadline);
                if (strlen($msg) !== $len) {
                    break; // cut short: judge on what was complete
                }
                $read += 2 + $len;
                $p = DnsMessage::parseAxfrMessage($msg, $id, $domain);
                if ($p['rcode'] !== 0 || ($m === 0 && ($p['records'] === [] || $p['records'][0]['type'] !== DnsMessage::SOA))) {
                    $status = $p['rcode'] === 5 || $p['rcode'] === 9 || $p['records'] === [] ? 'refused' : 'error';
                    break;
                }
                foreach ($p['records'] as $r) {
                    $records++;
                    if ($r['type'] !== DnsMessage::SOA) {
                        $data++;
                        if (count($sample) < 15 && !in_array($r['name'], $sample, true)) {
                            $sample[] = mb_substr((string) preg_replace('/[^a-z0-9._*?-]/', '?', $r['name']), 0, 120);
                        }
                    }
                }
                // Open only once a record of the zone itself arrived: a lone SOA could be a server's odd refusal.
                $status = $data > 0 ? 'open' : 'refused';
                if ($m > 0 && $p['records'] !== [] && end($p['records'])['type'] === DnsMessage::SOA) {
                    break; // the closing SOA: the whole zone was sent
                }
            }
        } catch (DnsException) {
            // malformed: whatever was decided so far stands (open only with zone records already read)
        }
        fclose($sock);
        return ['status' => $status, 'records' => $records, 'sample' => $sample];
    }

    /**
     * Whether $host can be taken over: its CNAME chain ends at a known cloud service that no longer exists.
     *
     * @return array{state:string, finding:?array{host:string, cname:string, provider:string, reason:string, evidence:string}}
     *         state 'found' (finding set; reason 'dangling': the target no longer resolves, or 'unclaimed': the provider's
     *         "no such site" page), 'clear' (checked, nothing to report) or 'unknown' (DNS or the web request failed:
     *         the caller keeps the earlier result, so one failed lookup never closes or opens a finding)
     */
    public function takeover(string $host): array
    {
        $clear = ['state' => 'clear', 'finding' => null];
        $unknown = ['state' => 'unknown', 'finding' => null];
        $target = $host;
        try {
            for ($hops = 0; $hops < 5; $hops++) {
                $next = null;
                foreach ($this->dns->query($target, DnsMessage::CNAME) as $a) {
                    if ($a['type'] === DnsMessage::CNAME) {
                        $next = strtolower(rtrim($a['data'], '.'));
                    }
                }
                if ($next === null || ScopeService::canonicalTarget($next) !== $next) {
                    break;
                }
                $target = $next;
            }
        } catch (DnsException) {
            return $unknown;
        }
        if ($target === $host) {
            return $clear; // no CNAME
        }
        $provider = null;
        foreach (self::PROVIDERS as $pattern => $p) {
            if (preg_match($pattern, $target) === 1) {
                $provider = $p;
                break;
            }
        }
        if ($provider === null) {
            return $clear;
        }
        $result = ['host' => $host, 'cname' => $target, 'provider' => $provider[0]];
        try {
            $ips = array_values(array_map(static fn (array $a): string => $a['data'],
                array_filter($this->dns->query($target, DnsMessage::A), static fn (array $a): bool => $a['type'] === DnsMessage::A)));
            $v6 = $ips === [] ? array_filter($this->dns->query($target, DnsMessage::AAAA), static fn (array $a): bool => $a['type'] === DnsMessage::AAAA) : [];
        } catch (DnsException) {
            return $unknown;
        }
        if ($ips === [] && $v6 === []) {
            // Neither IPv4 nor IPv6: the cloud name is gone. Only where anyone can register that name again is it a takeover.
            return $provider[2] ? ['state' => 'found', 'finding' => $result + ['reason' => 'dangling', 'evidence' => $host . ' → ' . $target . ' (no such name)']] : $clear;
        }
        if ($provider[1] === null || $ips === []) {
            return $clear;
        }
        if (filter_var($ips[0], FILTER_VALIDATE_IP) === false || !$this->publicAddress($ips[0])) {
            return $unknown; // never a request to a private or reserved address
        }
        // One request to the client's own name, at the address it resolves to: does the provider say "no such site"?
        foreach ([['https', 443], ['http', 80]] as [$scheme, $port]) {
            $page = $this->http->fetch($ips[0], $port, $scheme, $host);
            if (($page['ok'] ?? false) === true) {
                $body = (string) ($page['_response']['body'] ?? '');
                return str_contains($body, $provider[1])
                    ? ['state' => 'found', 'finding' => $result + ['reason' => 'unclaimed', 'evidence' => $host . ' → ' . $target . ': "' . $provider[1] . '"']]
                    : $clear;
            }
        }
        return $unknown;
    }
}

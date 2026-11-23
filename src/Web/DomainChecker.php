<?php

declare(strict_types=1);

namespace Sentinel\Web;

use Sentinel\Discovery\DnsClient;
use Sentinel\Discovery\DnsException;
use Sentinel\Discovery\DnsMessage;
use Sentinel\Scanning\Connector;
use Sentinel\Scanning\HttpProbe;
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
 * are usually third parties: each gets one standard request (the owner agreed to that for these checks).
 *
 * Untrusted: every DNS answer and web page (parsed strictly, length-limited, shown escaped).
 */
final class DomainChecker
{
    private const TIMEOUT = 5.0;
    private const MAX_AXFR_BYTES = 1_048_576;

    /**
     * Cloud services whose unclaimed names can be taken over: CNAME suffix => [provider, text of its "no such site"
     * page (null: only a target that no longer resolves counts)].
     */
    public const PROVIDERS = [
        '.s3.amazonaws.com' => ['Amazon S3', 'NoSuchBucket'],
        '.s3-website-us-east-1.amazonaws.com' => ['Amazon S3 website', 'NoSuchBucket'],
        '.amazonaws.com' => ['Amazon Web Services', 'NoSuchBucket'],
        '.github.io' => ['GitHub Pages', "There isn't a GitHub Pages site here"],
        '.herokuapp.com' => ['Heroku', 'No such app'],
        '.herokudns.com' => ['Heroku', 'No such app'],
        '.azurewebsites.net' => ['Azure App Service', null],
        '.cloudapp.net' => ['Azure Cloud Services', null],
        '.cloudapp.azure.com' => ['Azure virtual machine', null],
        '.trafficmanager.net' => ['Azure Traffic Manager', null],
        '.blob.core.windows.net' => ['Azure Storage', null],
        '.azureedge.net' => ['Azure CDN', null],
        '.elasticbeanstalk.com' => ['AWS Elastic Beanstalk', null],
        '.myshopify.com' => ['Shopify', 'Sorry, this shop is currently unavailable'],
        '.ghost.io' => ['Ghost', 'The thing you were looking for is no longer here'],
        '.zendesk.com' => ['Zendesk', 'Help Center Closed'],
        '.pantheonsite.io' => ['Pantheon', 'The gods are wise'],
        '.fastly.net' => ['Fastly', 'Fastly error: unknown domain'],
        '.surge.sh' => ['Surge', 'project not found'],
        '.readthedocs.io' => ['Read the Docs', 'unknown to Read the Docs'],
    ];

    public function __construct(private readonly DnsClient $dns, private readonly Connector $connector, private readonly HttpProbe $http)
    {
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
                        if ($a['type'] === $type && filter_var($a['data'], FILTER_VALIDATE_IP) !== false) {
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
        $id = random_int(0, 0xffff);
        $q = DnsMessage::buildAxfr($id, $domain);
        fwrite($sock, pack('n', strlen($q)) . $q);
        $records = 0;
        $sample = [];
        $status = 'error';
        $read = 0;
        $deadline = microtime(true) + self::TIMEOUT;
        try {
            for ($m = 0; $m < 10 && microtime(true) < $deadline && $read < self::MAX_AXFR_BYTES; $m++) {
                $lenBytes = (string) fread($sock, 2);
                if (strlen($lenBytes) !== 2) {
                    break;
                }
                $len = unpack('n', $lenBytes)[1];
                $msg = '';
                while (strlen($msg) < $len && !feof($sock) && microtime(true) < $deadline) {
                    $chunk = fread($sock, $len - strlen($msg));
                    if ($chunk === false || $chunk === '') {
                        break;
                    }
                    $msg .= $chunk;
                }
                $read += 2 + strlen($msg);
                $p = DnsMessage::parseAxfrMessage($msg, $id);
                if ($p['rcode'] !== 0 || ($m === 0 && ($p['records'] === [] || $p['records'][0]['type'] !== DnsMessage::SOA))) {
                    $status = $p['rcode'] === 5 || $p['rcode'] === 9 || $p['records'] === [] ? 'refused' : 'error';
                    break;
                }
                $status = 'open';
                foreach ($p['records'] as $r) {
                    $records++;
                    if (count($sample) < 15 && $r['type'] !== DnsMessage::SOA && !in_array($r['name'], $sample, true)) {
                        $sample[] = mb_substr((string) preg_replace('/[^a-z0-9._*-]/', '?', $r['name']), 0, 120);
                    }
                }
                if ($m > 0 && $p['records'] !== [] && end($p['records'])['type'] === DnsMessage::SOA) {
                    break; // the closing SOA: the whole zone was sent
                }
            }
        } catch (DnsException) {
            // malformed: whatever was decided so far stands
        }
        fclose($sock);
        return ['status' => $status, 'records' => $records, 'sample' => $sample];
    }

    /**
     * Whether $host can be taken over: its CNAME chain ends at a known cloud service that no longer exists.
     *
     * @return array{host:string, cname:string, provider:string, reason:string, evidence:string}|null reason: 'dangling'
     *         (the target no longer resolves) or 'unclaimed' (the provider's "no such site" page); null when fine or unknown
     */
    public function takeover(string $host): ?array
    {
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
            return null;
        }
        if ($target === $host) {
            return null; // no CNAME
        }
        $provider = null;
        foreach (self::PROVIDERS as $suffix => $p) {
            if (str_ends_with($target, $suffix)) {
                $provider = $p;
                break;
            }
        }
        if ($provider === null) {
            return null;
        }
        $result = ['host' => $host, 'cname' => $target, 'provider' => $provider[0]];
        try {
            $ips = array_values(array_filter(array_map(static fn (array $a): string => $a['data'],
                array_filter($this->dns->query($target, DnsMessage::A), static fn (array $a): bool => $a['type'] === DnsMessage::A))));
        } catch (DnsException) {
            return null; // can't tell
        }
        if ($ips === []) {
            try {
                $v6 = array_filter($this->dns->query($target, DnsMessage::AAAA), static fn (array $a): bool => $a['type'] === DnsMessage::AAAA);
            } catch (DnsException) {
                return null;
            }
            // Neither IPv4 nor IPv6: the cloud name is gone, and whoever registers it again gets the client's name.
            return $v6 === [] ? $result + ['reason' => 'dangling', 'evidence' => $host . ' → ' . $target . ' (no such name)'] : null;
        }
        if ($provider[1] === null || filter_var($ips[0], FILTER_VALIDATE_IP) === false) {
            return null;
        }
        // One request to the client's own name, at the address it resolves to: does the provider say "no such site"?
        foreach ([['https', 443], ['http', 80]] as [$scheme, $port]) {
            $page = $this->http->fetch($ips[0], $port, $scheme, $host);
            if (($page['ok'] ?? false) === true) {
                $body = (string) ($page['_response']['body'] ?? '');
                return str_contains($body, $provider[1])
                    ? $result + ['reason' => 'unclaimed', 'evidence' => $host . ' → ' . $target . ': "' . $provider[1] . '"']
                    : null;
            }
        }
        return null;
    }
}

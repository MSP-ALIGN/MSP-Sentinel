<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

/**
 * Extracts open TCP ports and service details from nmap's XML output.
 *
 * Security assumptions:
 * - The XML comes from nmap, but its contents (banners, product strings)
 *   come from the scanned host, so they are UNTRUSTED. Every value is
 *   type-checked, stripped of control characters and length-limited. Views
 *   escape them as usual.
 * - The parser never loads external entities or the network
 *   (LIBXML_NONET; PHP 8 doesn't substitute entities by default), and it
 *   refuses oversized input.
 */
final class NmapXmlParser
{
    private const MAX_BYTES = 5_000_000;

    /**
     * Hosts that are up in a discovery sweep (nmap -sn), with the MAC address when nmap reports one.
     * Output cut short (a sweep stopped, timed out or too large) still gives the hosts in its complete
     * <host> elements: each one is read on its own.
     *
     * @return list<array{ip:string, mac:string}>
     * @throws \RuntimeException when there is no usable output at all.
     */
    public static function parseDiscovery(string $xml, int $max = 200000): array
    {
        if ($xml === '' || strlen($xml) > 60_000_000 || !str_contains($xml, '<nmaprun')) {
            throw new \RuntimeException('nmap produced no usable output.');
        }
        preg_match_all('#<host[\s>].*?</host>#s', $xml, $m);
        $out = [];
        $previous = libxml_use_internal_errors(true);
        try {
            foreach ($m[0] as $block) {
                $host = simplexml_load_string($block, \SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOCDATA);
                if ($host === false) {
                    continue;
                }
            if ((string) ($host->status['state'] ?? '') !== 'up') {
                continue;
            }
            $ip = '';
            $mac = '';
            foreach ($host->address as $a) {
                $type = (string) $a['addrtype'];
                if (($type === 'ipv4' || $type === 'ipv6') && filter_var((string) $a['addr'], FILTER_VALIDATE_IP) !== false) {
                    $ip = inet_ntop((string) inet_pton((string) $a['addr']));
                } elseif ($type === 'mac' && preg_match('/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/', (string) $a['addr'])) {
                    $mac = strtolower((string) $a['addr']);
                }
            }
            if ($ip !== '') {
                $out[$ip] = ['ip' => $ip, 'mac' => $mac];
            }
            if (count($out) >= $max) {
                break;
            }
            }
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
        return array_values($out);
    }

    /**
     * @param string $xml       nmap -oX output for one host.
     * @param string $expectIp  The address that was scanned. Hosts with any other address are ignored.
     * @return array{complete:bool, open:list<array{port:int,service:string,product:string,version:string,extra:string,cpe:string,scripts:list<array{id:string,output:string}>}>,
     *               hostscripts:list<array{id:string,output:string}>}  scripts: nmap script results (engagements only), untrusted text
     * @throws \RuntimeException if the XML can't be parsed at all.
     */
    public static function parse(string $xml, string $expectIp, int $maxBytes = self::MAX_BYTES): array
    {
        if ($xml === '' || strlen($xml) > $maxBytes) {
            throw new \RuntimeException('nmap produced no usable output.');
        }
        $previous = libxml_use_internal_errors(true);
        try {
            $doc = simplexml_load_string($xml, \SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOCDATA);
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
        if ($doc === false || $doc->getName() !== 'nmaprun') {
            throw new \RuntimeException('nmap output is not valid XML.');
        }
        $runFinished = isset($doc->runstats->finished) && (string) $doc->runstats->finished['exit'] === 'success';
        // "Complete" means nmap really finished THIS host: the run succeeded, the host is present,
        // it didn't hit nmap's host timeout, and it has a <ports> section. Only then may ports
        // missing from the output be treated as closed. A timeout must never "close" open services.
        $hostComplete = false;
        $open = [];
        $hostScripts = [];
        foreach ($doc->host as $host) {
            $addr = (string) ($host->address['addr'] ?? '');
            if ($addr === '' || @inet_pton($addr) !== @inet_pton($expectIp)) {
                continue;
            }
            $hostComplete = (string) ($host['timedout'] ?? '') !== 'true' && isset($host->ports);
            $hostScripts = self::scripts($host->hostscript->script ?? []);
            foreach ($host->ports->port ?? [] as $port) {
                if ((string) $port['protocol'] !== 'tcp' || (string) ($port->state['state'] ?? '') !== 'open') {
                    continue;
                }
                $num = (int) $port['portid'];
                if ($num < 1 || $num > 65535) {
                    continue;
                }
                $svc = $port->service;
                $cpe = isset($svc->cpe) ? (string) $svc->cpe[0] : '';
                $open[] = [
                    'port' => $num,
                    'service' => self::clean((string) ($svc['name'] ?? ''), 100),
                    'product' => self::clean((string) ($svc['product'] ?? ''), 200),
                    'version' => self::clean((string) ($svc['version'] ?? ''), 100),
                    'extra' => self::clean((string) ($svc['extrainfo'] ?? ''), 200),
                    'cpe' => str_starts_with($cpe, 'cpe:/') ? self::clean($cpe, 255) : '',
                    'scripts' => self::scripts($port->script ?? []),
                ];
            }
        }
        return ['complete' => $runFinished && $hostComplete, 'open' => $open, 'hostscripts' => $hostScripts];
    }

    /**
     * nmap script results: id and output (lines kept, control characters removed, at most 4,000 characters each,
     * 40 scripts). Untrusted text from the scanned host.
     *
     * @param iterable<\SimpleXMLElement> $nodes
     * @return list<array{id:string,output:string}>
     */
    private static function scripts(iterable $nodes): array
    {
        $out = [];
        foreach ($nodes as $sc) {
            $id = (string) ($sc['id'] ?? '');
            if (preg_match('/^[a-z0-9][a-z0-9-]{0,60}$/', $id) !== 1) {
                continue;
            }
            $text = mb_convert_encoding((string) ($sc['output'] ?? ''), 'UTF-8', 'UTF-8');
            $text = (string) preg_replace('/[\x00-\x08\x0B-\x1F\x7F]/u', ' ', $text);
            $out[] = ['id' => $id, 'output' => mb_substr(trim($text), 0, 4000)];
            if (count($out) >= 40) {
                break;
            }
        }
        return $out;
    }

    /** Remove control characters and invalid UTF-8, then cut to $max characters. */
    private static function clean(string $value, int $max): string
    {
        $value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        $value = (string) preg_replace('/[\x00-\x1F\x7F]/u', ' ', $value);
        return mb_substr(trim($value), 0, $max);
    }
}

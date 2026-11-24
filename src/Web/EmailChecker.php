<?php

declare(strict_types=1);

namespace Sentinel\Web;

use Sentinel\Discovery\DnsClient;
use Sentinel\Discovery\DnsException;
use Sentinel\Discovery\DnsMessage;

/**
 * Email security records for a domain: SPF, DMARC and DKIM (common
 * selectors), through DNS only. Nothing is sent to the client's servers.
 *
 * Only domains that receive mail (have MX records) are judged; a domain
 * without MX isn't flagged for missing records.
 *
 * Security assumptions: DNS answers are untrusted text, only matched with
 * fixed patterns and stored short. Domains come from the client's active
 * authorisation (scope), checked by the caller.
 */
final class EmailChecker
{
    /** Common DKIM selectors (Microsoft 365, Google, generic). A miss is "not found", not "missing". */
    public const DKIM_SELECTORS = ['selector1', 'selector2', 'google', 'default', 'k1', 's1', 'mail', 'dkim'];

    /** Uses the configured resolver. */
    public function __construct(private readonly DnsClient $dns)
    {
    }

    /**
     * Check one domain.
     *
     * @param string|null $orgDomain The parent (organisational) domain, only when it is in scope too: its
     *        DMARC record applies when the domain has none of its own (sp= or p=).
     * @return array{domain:string, has_mx:bool, spf:string, spf_all:string, dmarc:string, dmarc_policy:string, dkim:list<string>, issues:list<string>, info:list<string>, error:string}
     */
    public function check(string $domain, ?string $orgDomain = null): array
    {
        $out = ['domain' => $domain, 'has_mx' => false, 'spf' => '', 'spf_all' => '', 'dmarc' => '', 'dmarc_policy' => '', 'dkim' => [], 'issues' => [], 'info' => [], 'error' => ''];
        try {
            // A "null MX" (exchange ".", RFC 7505) says the domain accepts no email.
            $out['has_mx'] = array_filter($this->records($domain, DnsMessage::MX), static fn (string $x): bool => trim($x, '. ') !== '') !== [];
            if (!$out['has_mx']) {
                return $out;
            }
            $spf = array_values(array_filter($this->records($domain, DnsMessage::TXT), static fn (string $t): bool => preg_match('/^v=spf1(\s|$)/i', $t) === 1));
            if ($spf === []) {
                $out['issues'][] = 'spf_missing';
            } elseif (count($spf) > 1) {
                $out['issues'][] = 'spf_multiple'; // receivers treat two SPF records as an error
                $out['spf'] = mb_substr($spf[0], 0, 500);
            } else {
                $out['spf'] = mb_substr($spf[0], 0, 500);
                if (preg_match('/(^|\s)([-~?+]?)all(\s|$)/i', $spf[0], $m)) {
                    $out['spf_all'] = $m[2] === '' ? '+' : $m[2];
                }
                if ($out['spf_all'] === '' && preg_match('/(^|\s)redirect=\S+/i', $spf[0])) {
                    $out['spf_all'] = 'redirect'; // the policy comes from the redirect target (RFC 7208); not judged
                }
                if ($out['spf_all'] === '+') {
                    $out['issues'][] = 'spf_pass_all';
                } elseif ($out['spf_all'] === '?' || $out['spf_all'] === '') {
                    $out['issues'][] = 'spf_weak';
                }
            }
            $dmarc = $this->dmarc($domain);
            $policyTag = 'p';
            if ($dmarc === [] && $orgDomain !== null) {
                $dmarc = $this->dmarc($orgDomain);
                $policyTag = 'sp'; // subdomain policy of the organisational domain, falling back to its p=
                $out['dmarc_from'] = $orgDomain;
            }
            if ($dmarc === []) {
                $out['issues'][] = 'dmarc_missing';
            } else {
                $out['dmarc'] = mb_substr($dmarc[0], 0, 500);
                $policy = static fn (string $tag): string => preg_match('/;\s*' . $tag . '\s*=\s*(none|quarantine|reject)/i', $dmarc[0], $m) ? strtolower($m[1]) : '';
                $out['dmarc_policy'] = ($policyTag === 'sp' ? $policy('sp') : '') ?: $policy('p');
                if ($out['dmarc_policy'] === 'none' || $out['dmarc_policy'] === '') {
                    $out['issues'][] = 'dmarc_weak';
                }
            }
            foreach (self::DKIM_SELECTORS as $sel) {
                foreach ($this->records($sel . '._domainkey.' . $domain, DnsMessage::TXT) as $t) {
                    if (preg_match('/(^|;)\s*(v=DKIM1|k=rsa|p=[A-Za-z0-9+\/]{20,})/i', $t)) {
                        $out['dkim'][] = $sel;
                        break;
                    }
                }
            }
            if ($out['dkim'] === []) {
                $out['info'][] = 'dkim_not_found';
            }
        } catch (DnsException $ex) {
            $out['error'] = mb_substr($ex->getMessage(), 0, 200);
        }
        return $out;
    }

    /**
     * DMARC records published for a domain.
     *
     * @return list<string>
     */
    private function dmarc(string $domain): array
    {
        return array_values(array_filter($this->records('_dmarc.' . $domain, DnsMessage::TXT), static fn (string $t): bool => preg_match('/^v=DMARC1\s*;/i', $t) === 1));
    }

    /**
     * Data of the answers of one type for one name ([] for NXDOMAIN or no records).
     *
     * @return list<string>
     */
    private function records(string $name, int $type): array
    {
        // DnsClient returns the answers ([] for NXDOMAIN) and throws on server errors and bad replies.
        $answers = $this->dns->query($name, $type);
        return array_values(array_map(static fn (array $a): string => (string) $a['data'],
            array_filter($answers, static fn (array $a): bool => $a['type'] === $type)));
    }
}

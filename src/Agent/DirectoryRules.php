<?php

declare(strict_types=1);

namespace Sentinel\Agent;

/**
 * Grading of what the agent found in a site's Active Directory, and of name requests it heard (Balanced, as agreed
 * with the owner):
 * - Fail: accounts that can be cracked offline without knowing a password (AS-REP roastable); admin accounts with a
 *   service name (Kerberoastable admins); computers other than domain controllers trusted for unconstrained
 *   delegation; devices sending LLMNR/NetBIOS name requests (poisoning).
 * - Warning: other Kerberoastable accounts; more than MAX_DOMAIN_ADMINS Domain Admins; admin passwords that never
 *   expire; a krbtgt password older than KRBTGT_DAYS; LAPS missing; LDAP signing not required; stale admin accounts.
 *
 * Only what the agent actually read counts: a check missing from the results (a failed read, an older agent) is no
 * finding, and keeps nothing open by itself; the stored results only change on a successful read.
 * Untrusted: the results (validated and shortened at ingest; names are escaped wherever shown).
 */
final class DirectoryRules
{
    public const MAX_DOMAIN_ADMINS = 5;
    public const KRBTGT_DAYS = 365;
    /** Names listed in a finding at most. */
    public const NAMES_SHOWN = 25;

    /**
     * Findings from a site's directory results.
     *
     * @param array<string,mixed> $r
     * @return list<array{code:string, severity:string, text:string, detail:string, evidence:string}>
     */
    public static function issues(array $r): array
    {
        $out = [];
        $list = static function (string $code, string $severity, string $text, string $intro) use (&$out, $r): void {
            $l = $r[$code] ?? null;
            if (is_array($l) && (int) ($l['count'] ?? 0) > 0) {
                $out[] = ['code' => $code, 'severity' => $severity, 'text' => $text, 'detail' => $intro . ' ' . self::names($l), 'evidence' => $code . '|' . self::fingerprint($l)];
            }
        };
        $list('asrep', 'fail', __('Accounts can be cracked offline without a password (AS-REP roasting)'),
            __('These enabled accounts do not require Kerberos pre-authentication, so anyone on the network can request data to crack their passwords offline:'));
        $list('kerberoast_admin', 'fail', __('Admin accounts can be cracked offline (Kerberoasting)'),
            __('These enabled admin accounts have a service name (SPN), so any domain user can request a ticket to crack their passwords offline:'));
        $list('unconstrained', 'fail', __('Computers trusted for unconstrained delegation'),
            __('These computers (not domain controllers) can act as any user who connects to them; taking one over can give an attacker domain admin rights:'));
        $list('kerberoast', 'warn', __('Service accounts can be cracked offline (Kerberoasting)'),
            __('These enabled accounts have a service name (SPN), so any domain user can request a ticket to crack their passwords offline:'));
        $list('admin_never_expires', 'warn', __('Admin passwords never expire'),
            __('These enabled admin accounts have "password never expires" set:'));
        $list('stale_admins', 'warn', __('Unused admin accounts are still enabled'),
            __('These enabled admin accounts have not signed in for 90 days or more (or never):'));
        $da = $r['domain_admins'] ?? null;
        if (is_array($da) && (int) ($da['count'] ?? 0) > self::MAX_DOMAIN_ADMINS) {
            $out[] = ['code' => 'domain_admins', 'severity' => 'warn', 'text' => __('Too many Domain Admins ({n})', ['n' => (int) $da['count']]),
                      'detail' => __('More than {max} accounts are direct members of Domain Admins:', ['max' => self::MAX_DOMAIN_ADMINS]) . ' ' . self::names($da),
                      'evidence' => 'domain_admins|' . self::fingerprint($da)];
        }
        if (is_int($r['krbtgt_age_days'] ?? null) && $r['krbtgt_age_days'] > self::KRBTGT_DAYS) {
            $out[] = ['code' => 'krbtgt_old', 'severity' => 'warn', 'text' => __('The krbtgt password is {n} days old', ['n' => $r['krbtgt_age_days']]),
                      'detail' => __('The krbtgt account signs every Kerberos ticket. If it ever leaked, an attacker can forge tickets ("golden tickets") until it is changed (twice).'),
                      'evidence' => 'krbtgt_old|' . intdiv($r['krbtgt_age_days'], 365)];
        }
        $laps = $r['laps'] ?? null;
        if (is_array($laps) && ($laps['deployed'] ?? null) === false && (int) ($laps['eligible'] ?? 0) > 0) {
            $out[] = ['code' => 'laps_missing', 'severity' => 'warn', 'text' => __('LAPS is not in use'),
                      'detail' => __('None of the {n} computer(s) in use has a LAPS-managed local administrator password, so the local admin password is probably the same everywhere.', ['n' => (int) $laps['eligible']]),
                      'evidence' => 'laps_missing'];
        } elseif (is_array($laps) && (int) ($laps['count'] ?? 0) > 0) {
            $out[] = ['code' => 'laps_missing', 'severity' => 'warn', 'text' => __('Computers without LAPS'),
                      'detail' => __('These computers in use have no LAPS-managed local administrator password:') . ' ' . self::names($laps),
                      'evidence' => 'laps_missing|' . self::fingerprint($laps)];
        }
        if (($r['signing_required'] ?? null) === false) {
            $out[] = ['code' => 'ldap_signing', 'severity' => 'warn', 'text' => __('LDAP signing is not required'),
                      'detail' => __('The domain controller accepts unsigned LDAP sign-ins, so a machine in the middle can relay them (NTLM relay to LDAP).'),
                      'evidence' => 'ldap_signing'];
        }
        return $out;
    }

    /**
     * The finding for devices that sent LLMNR/NetBIOS name requests while the agent listened, or null.
     *
     * @param array<string,mixed> $n
     * @param callable(string):string $deviceName  a device's name for an address ('' when unknown)
     * @return array{code:string, severity:string, text:string, detail:string, evidence:string}|null
     */
    public static function nameIssue(array $n, callable $deviceName): ?array
    {
        $sources = array_values(array_filter((array) ($n['sources'] ?? []), 'is_array'));
        if ($sources === []) {
            return null;
        }
        $labels = [];
        $protocols = [];
        foreach ($sources as $s) {
            $ip = (string) ($s['ip'] ?? '');
            $name = $deviceName($ip);
            $labels[] = $name !== '' ? $name . ' (' . $ip . ')' : $ip;
            foreach ((array) ($s['protocols'] ?? []) as $p) {
                $protocols[(string) $p] = true;
            }
        }
        sort($labels, SORT_NATURAL);
        $what = implode(' / ', array_map(static fn (string $p): string => $p === 'llmnr' ? 'LLMNR' : 'NetBIOS', array_keys($protocols)));
        return ['code' => 'name_poisoning', 'severity' => 'fail', 'text' => __('Devices can be tricked into sending passwords (LLMNR/NetBIOS poisoning)'),
                'detail' => __('While listening for {s} seconds, the agent heard {what} name requests from these devices; a poisoning tool on the network could answer them and capture password hashes:', ['s' => (int) ($n['seconds'] ?? 0), 'what' => $what])
                    . ' ' . self::names(['count' => count($labels), 'names' => $labels]),
                'evidence' => 'name_poisoning'];
    }

    /** "a, b, c (and 4 more)". @param array<string,mixed> $l */
    private static function names(array $l): string
    {
        $names = array_slice(array_values(array_filter((array) ($l['names'] ?? []), 'is_string')), 0, self::NAMES_SHOWN);
        $more = max(0, (int) ($l['count'] ?? 0) - count($names));
        return implode(', ', $names) . ($more > 0 ? ' ' . __('(and {n} more)', ['n' => $more]) : '') . '.';
    }

    /** A short fingerprint of a name list, so a false positive is reopened when the accounts change. @param array<string,mixed> $l */
    private static function fingerprint(array $l): string
    {
        $names = array_map('strtolower', array_values(array_filter((array) ($l['names'] ?? []), 'is_string')));
        sort($names);
        return substr(hash('sha256', implode("\n", $names)), 0, 16);
    }
}

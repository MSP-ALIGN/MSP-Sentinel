<?php

declare(strict_types=1);

namespace Sentinel\Directory;

/**
 * The agent's Active Directory checks (read-only), run during a full scan when the signed job asks for them.
 *
 * Order, and what is sent where:
 * 1. The plain LDAP port (389) is asked whether it requires signing, with a made-up account (LdapClient).
 * 2. LDAPS (636): the TLS handshake gives the domain controller's certificate. Its SHA-256 fingerprint must equal the
 *    one an admin trusted in Sentinel (in the signed job). If it doesn't (or none is trusted yet), the agent stops
 *    here and only reports the certificate: the password is never sent to a certificate nobody trusted.
 * 3. Bind with the read-only account, then three searches: users, the Domain Admins group, computers.
 * The weaknesses are worked out here, so only results go back: for each check a count and up to MAX_NAMES account
 * names. No password hashes or secrets are read (the attributes asked for are listed in the searches below).
 *
 * Untrusted: every directory value (names are cleaned and shortened; numbers parsed defensively).
 */
final class DirectoryChecks
{
    /** Names sent per check at most (Sentinel shows 25). */
    public const MAX_NAMES = 200;
    /** An admin account that hasn't signed in for this many days is stale. */
    public const STALE_DAYS = 90;
    private const UAC_DISABLED = 0x2;
    private const UAC_SERVER_TRUST = 0x2000;
    private const UAC_NO_EXPIRY = 0x10000;
    private const UAC_TRUSTED_FOR_DELEGATION = 0x80000;
    private const UAC_NO_PREAUTH = 0x400000;
    /** primaryGroupID of domain controllers (516) and read-only domain controllers (521). */
    private const DC_GROUPS = [516, 521];

    /** @param callable(string,int):array{0:string,1:int} $endpoint maps (ip, port) to where to connect (Connector) */
    public function __construct(private $endpoint, private readonly float $timeout = 120.0)
    {
    }

    /**
     * Run the checks.
     *
     * @param array{domain:string, dc_ip:string, cert_trusted:string} $job  the signed job's directory settings
     * @return array{cert:array<string,string>, signing_required:?bool, bind:string, error:string, checks:?array<string,mixed>}
     *   bind: ok | untrusted_certificate | no_password | refused | failed
     */
    public function run(array $job, string $username, ?string $password, ?int $now = null): array
    {
        $now ??= time();
        $out = ['cert' => [], 'signing_required' => null, 'bind' => 'failed', 'error' => '', 'checks' => null];
        [$ip389, $port389] = ($this->endpoint)($job['dc_ip'], 389);
        $out['signing_required'] = LdapClient::signingRequired($ip389, $port389);
        [$ip, $port] = ($this->endpoint)($job['dc_ip'], 636);
        try {
            $c = LdapClient::connectTls($ip, $port, $this->timeout);
        } catch (LdapException $ex) {
            $out['error'] = $ex->getMessage();
            return $out;
        }
        try {
            $out['cert'] = $c->certificate();
            if ($job['cert_trusted'] === '' || !hash_equals($job['cert_trusted'], $out['cert']['sha256'])) {
                $out['bind'] = 'untrusted_certificate';
                $out['error'] = $job['cert_trusted'] === '' ? 'Waiting for an admin to trust the domain controller\'s certificate.'
                    : 'The domain controller\'s certificate changed: the password was not sent. Trust the new certificate in Sentinel if the change is expected.';
                return $out;
            }
            if ($password === null || $password === '') {
                $out['bind'] = 'no_password';
                $out['error'] = 'The agent has no directory password: set it on the client\'s Agents page.';
                return $out;
            }
            $code = $c->bind($username, $password);
            if ($code !== LdapClient::SUCCESS) {
                $out['bind'] = 'refused';
                $out['error'] = $code === LdapClient::INVALID_CREDENTIALS ? 'The domain controller refused the account (wrong password, or the account is locked or disabled).'
                    : 'The domain controller refused the sign-in (LDAP result ' . $code . ').';
                return $out;
            }
            $out['bind'] = 'ok';
            $out['checks'] = $this->read($c, self::baseDn($job['domain']), $now);
        } catch (LdapException | BerException $ex) {
            $out['error'] = $ex->getMessage();
        } finally {
            $c->close();
        }
        return $out;
    }

    /** "corp.example" -> "DC=corp,DC=example". */
    public static function baseDn(string $domain): string
    {
        return implode(',', array_map(static fn (string $p): string => 'DC=' . $p, explode('.', $domain)));
    }

    /**
     * The three searches and the checks.
     *
     * @return array<string,mixed>
     */
    private function read(LdapClient $c, string $base, int $now): array
    {
        $users = $c->search($base, LdapClient::SCOPE_SUBTREE, ['and', [['eq', 'objectCategory', 'person'], ['eq', 'objectClass', 'user']]],
            ['sAMAccountName', 'userAccountControl', 'servicePrincipalName', 'adminCount', 'pwdLastSet', 'lastLogonTimestamp', 'primaryGroupID']);
        // Domain Admins by its well-known SID (the domain's SID + 512), so localised names ("Domänen-Admins") are found;
        // by its English name only when the domain's SID can't be read.
        $groups = [];
        $domain = $c->search($base, LdapClient::SCOPE_BASE, ['present', 'objectClass'], ['objectSid'], 1);
        $daSid = self::domainAdminsSid((string) ($domain[0]['attrs']['objectsid'][0] ?? ''));
        if ($daSid !== null) {
            $groups = $c->search($base, LdapClient::SCOPE_SUBTREE, ['eq', 'objectSid', $daSid], ['member'], 5);
        }
        if ($groups === []) {
            $groups = $c->search($base, LdapClient::SCOPE_SUBTREE, ['and', [['eq', 'objectClass', 'group'], ['eq', 'sAMAccountName', 'Domain Admins']]], ['member'], 5);
        }
        $computers = $c->search($base, LdapClient::SCOPE_SUBTREE, ['eq', 'objectCategory', 'computer'],
            ['sAMAccountName', 'userAccountControl', 'primaryGroupID', 'lastLogonTimestamp', 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime']);

        // Domain Admins (direct members; their names from the member DNs).
        $daNames = [];
        $daGroup = $groups[0] ?? null;
        foreach ($daGroup['attrs']['member'] ?? [] as $dn) {
            $daNames[] = self::cn($dn);
        }
        // Members whose PRIMARY group is Domain Admins (primaryGroupID 512) are not listed in "member".
        foreach ($users as $u) {
            if (self::num($u, 'primarygroupid') === 512 && !(self::num($u, 'useraccountcontrol') & self::UAC_DISABLED)) {
                $cn = self::cn($u['dn']);
                if (!in_array(strtolower($cn), array_map('strtolower', $daNames), true)) {
                    $daNames[] = $cn;
                }
            }
        }
        $daLower = array_map('strtolower', $daNames);

        $asrep = $kerbAdmin = $kerb = $neverExpires = $stale = [];
        $krbtgtAge = null;
        foreach ($users as $u) {
            $name = self::name($u);
            $uac = self::num($u, 'useraccountcontrol');
            if (strtolower($name) === 'krbtgt') {
                $set = self::filetime(self::first($u, 'pwdlastset'));
                $krbtgtAge = $set === null ? null : intdiv(max(0, $now - $set), 86400);
                continue;
            }
            if ($uac & self::UAC_DISABLED) {
                continue; // disabled accounts can't be used
            }
            $admin = self::num($u, 'admincount') === 1 || in_array(strtolower(self::cn($u['dn'])), $daLower, true);
            if ($uac & self::UAC_NO_PREAUTH) {
                $asrep[] = $name;
            }
            if (($u['attrs']['serviceprincipalname'] ?? []) !== []) {
                if ($admin) {
                    $kerbAdmin[] = $name;
                } else {
                    $kerb[] = $name;
                }
            }
            if ($admin && ($uac & self::UAC_NO_EXPIRY)) {
                $neverExpires[] = $name;
            }
            $last = self::filetime(self::first($u, 'lastlogontimestamp'));
            if ($admin && ($last === null || $last < $now - self::STALE_DAYS * 86400)) {
                $stale[] = $name;
            }
        }

        $unconstrained = $lapsMissing = [];
        $lapsSeen = false;
        $eligible = 0;
        foreach ($computers as $m) {
            $uac = self::num($m, 'useraccountcontrol');
            $isDc = ($uac & self::UAC_SERVER_TRUST) || in_array(self::num($m, 'primarygroupid'), self::DC_GROUPS, true);
            if (($uac & self::UAC_DISABLED) || $isDc) {
                continue; // domain controllers are trusted for delegation by design and don't use LAPS
            }
            $name = rtrim(self::name($m), '$');
            if ($uac & self::UAC_TRUSTED_FOR_DELEGATION) {
                $unconstrained[] = $name;
            }
            $hasLaps = self::first($m, 'ms-mcs-admpwdexpirationtime') !== '' || self::first($m, 'mslaps-passwordexpirationtime') !== '';
            $lapsSeen = $lapsSeen || $hasLaps;
            $last = self::filetime(self::first($m, 'lastlogontimestamp'));
            if ($last !== null && $last >= $now - self::STALE_DAYS * 86400) { // only computers in use
                $eligible++;
                if (!$hasLaps) {
                    $lapsMissing[] = $name;
                }
            }
        }
        $list = static function (array $names): array {
            sort($names, SORT_NATURAL | SORT_FLAG_CASE);
            return ['count' => count($names), 'names' => array_slice($names, 0, self::MAX_NAMES)];
        };
        return [
            'users' => count($users), 'computers' => count($computers),
            'asrep' => $list($asrep), 'kerberoast_admin' => $list($kerbAdmin), 'kerberoast' => $list($kerb),
            'admin_never_expires' => $list($neverExpires), 'stale_admins' => $list($stale),
            'domain_admins' => $daGroup === null ? null : $list($daNames),
            'krbtgt_age_days' => $krbtgtAge,
            'unconstrained' => $list($unconstrained),
            'laps' => ['deployed' => $lapsSeen, 'eligible' => $eligible] + $list($lapsMissing),
        ];
    }

    /**
     * The binary SID of Domain Admins from the domain's binary objectSid (revision, sub-authority count, 6-byte
     * authority, 32-bit little-endian sub-authorities): one more sub-authority, 512. Null when it isn't a domain SID.
     */
    public static function domainAdminsSid(string $domainSid): ?string
    {
        $len = strlen($domainSid);
        if ($len < 8 || ord($domainSid[0]) !== 1) {
            return null;
        }
        $count = ord($domainSid[1]);
        if ($count < 1 || $count > 14 || $len !== 8 + 4 * $count) {
            return null;
        }
        return chr(1) . chr($count + 1) . substr($domainSid, 2) . pack('V', 512);
    }

    /** @param array{dn:string, attrs:array<string,list<string>>} $e */
    private static function first(array $e, string $attr): string
    {
        return (string) ($e['attrs'][$attr][0] ?? '');
    }

    /** @param array{dn:string, attrs:array<string,list<string>>} $e */
    private static function num(array $e, string $attr): int
    {
        $v = self::first($e, $attr);
        return preg_match('/^-?\d{1,19}$/', $v) === 1 ? (int) $v : 0;
    }

    /** An account name, cleaned and shortened. @param array{dn:string, attrs:array<string,list<string>>} $e */
    private static function name(array $e): string
    {
        $n = self::first($e, 'samaccountname');
        return self::clean($n !== '' ? $n : self::cn($e['dn']));
    }

    /** The first CN of a DN ("CN=Jo Example,OU=..." -> "Jo Example"), cleaned. */
    private static function cn(string $dn): string
    {
        return self::clean(preg_match('/^CN=((?:\\\\.|[^,\\\\])+)/i', $dn, $m) ? stripslashes($m[1]) : $dn);
    }

    private static function clean(string $s): string
    {
        return mb_substr(trim((string) preg_replace('/[\x00-\x1F\x7F]/u', '', mb_convert_encoding($s, 'UTF-8', 'UTF-8'))), 0, 100);
    }

    /** A Windows FILETIME (100 ns since 1601) as a Unix time; null for 0 / "never" / nonsense. */
    private static function filetime(string $v): ?int
    {
        if (preg_match('/^\d{1,19}$/', $v) !== 1 || $v === '0' || strlen($v) > 18) {
            return null;
        }
        $t = intdiv((int) $v, 10000000) - 11644473600;
        return $t > 0 ? $t : null;
    }
}

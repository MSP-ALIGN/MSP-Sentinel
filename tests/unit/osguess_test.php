<?php

declare(strict_types=1);

/**
 * Unit tests (1.38): the NTLM challenge parser (Windows version and names, hostile input) and the OS guesser
 * (Windows builds, shared client/server builds, banner clues). Made-up names only.
 */

use Sentinel\Inventory\OsGuess;
use Sentinel\Scanning\SmbShares;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$challenge = static function (int $major, int $minor, int $build, array $names, bool $versionFlag = true): string {
    $u16 = static fn (string $t): string => (string) mb_convert_encoding($t, 'UTF-16LE', 'UTF-8');
    $av = '';
    foreach ($names as $id => $text) {
        $av .= pack('vv', $id, strlen($u16($text))) . $u16($text);
    }
    $av .= pack('vv', 0, 0);
    return "NTLMSSP\0" . pack('V', 2) . pack('vvV', 0, 0, 56) . pack('V', $versionFlag ? 0x02888207 : 0x00888207) . str_repeat('x', 8) . str_repeat("\0", 8)
        . pack('vvV', strlen($av), strlen($av), 56) . pack('CCvCCCC', $major, $minor, $build, 0, 0, 0, 15) . $av;
};

return [
    'NTLM challenge: version and names read; hostile input refused' => function (TestContext $ctx) use ($challenge): void {
        $r = SmbShares::parseChallenge($challenge(10, 0, 22631, [1 => 'LAPTOP-07', 2 => 'EXAMPLE', 3 => 'laptop-07.corp.example', 4 => 'corp.example']));
        Assert::same(['major' => 10, 'minor' => 0, 'build' => 22631, 'netbios_name' => 'LAPTOP-07', 'netbios_domain' => 'EXAMPLE', 'dns_name' => 'laptop-07.corp.example', 'dns_domain' => 'corp.example'], $r);
        Assert::same(0, SmbShares::parseChallenge($challenge(10, 0, 22631, [1 => 'X1'], false))['major'], 'no version flag: no version');
        Assert::same('evilscriptname', SmbShares::parseChallenge($challenge(10, 0, 1, [1 => "evil<script>\x01name"]))['netbios_name'], 'names cleaned');
        Assert::same(null, SmbShares::parseChallenge('junk'));
        Assert::same(null, SmbShares::parseChallenge("NTLMSSP\0\x01\0\0\0" . str_repeat("\0", 60)), 'not a challenge');
        // Target info pointing past the end, or a pair running past it: no crash, no names.
        $bad = $challenge(10, 0, 20348, [1 => 'SRV']);
        $bad = substr($bad, 0, 40) . pack('vvV', 5000, 5000, 56) . substr($bad, 48);
        Assert::same('', SmbShares::parseChallenge($bad)['netbios_name']);
        Assert::same(20348, SmbShares::parseChallenge($bad)['build'], 'version still read');
    },
    'OS guess: Windows builds, shared client/server builds, banner clues' => function (TestContext $ctx): void {
        $ntlm = static fn (int $b, int $maj = 10, int $min = 0): array => ['major' => $maj, 'minor' => $min, 'build' => $b];
        $p = static fn (int ...$ports): array => array_map(static fn (int $x): array => ['port' => $x, 'product' => '', 'version' => '', 'extra_info' => ''], $ports);
        Assert::same(['Windows 11 23H2', 'workstation'], array_values(array_intersect_key(OsGuess::guess($ntlm(22631), $p(445)), ['os_name' => 1, 'device_class' => 1])));
        Assert::same('Windows Server 2022', OsGuess::guess($ntlm(20348), $p(445))['os_name']);
        Assert::same(['Windows 10 22H2', 'workstation'], [OsGuess::guess($ntlm(19045), $p(445))['os_name'], OsGuess::guess($ntlm(19045), $p(445, 88, 389))['device_class']]);
        Assert::same(['Windows Server 2025', 'server'], [OsGuess::guess($ntlm(26100), $p(445, 88, 389))['os_name'], OsGuess::guess($ntlm(26100), $p(445, 88))['device_class']], 'shared build + DC ports');
        Assert::same(['Windows 11 24H2 or Windows Server 2025', 'other'], [OsGuess::guess($ntlm(26100), $p(445))['os_name'], OsGuess::guess($ntlm(26100), $p(445))['device_class']], 'shared build, no clue');
        Assert::same('Windows 8.1 or Server 2012 R2', OsGuess::guess($ntlm(9600, 6, 3), $p(445))['os_name']);
        Assert::same('26100', OsGuess::guess($ntlm(26100), $p(445))['os_build']);
        $b = static fn (string $product, int $port = 22): array => [['port' => $port, 'product' => $product, 'version' => '', 'extra_info' => '']];
        Assert::same('Ubuntu Linux', OsGuess::guess(null, $b('OpenSSH 8.9p1 Ubuntu 3ubuntu0.6'))['os_name']);
        Assert::same('Linux or Unix (Samba)', OsGuess::guess(['major' => 6, 'minor' => 1, 'build' => 0], $b('Samba smbd 4.6.2', 445))['os_name'], 'Samba is not Windows');
        Assert::same('Printer', OsGuess::guess(null, $p(9100, 80))['os_name']);
        Assert::same('Synology DSM (NAS)', OsGuess::guess(null, $b('Synology DiskStation Manager', 5001))['os_name']);
        Assert::same('NAS', OsGuess::guess(null, [['port' => 443, 'product' => '', 'version' => '', 'extra_info' => '', 'web' => ['category' => 'nas_admin']]])['os_name']);
        Assert::same(null, OsGuess::guess(null, $p(8080)), 'nothing known');
        Assert::same(null, OsGuess::guess(['major' => 'x', 'build' => -1], $p(8080)), 'hostile NTLM values ignored');
    },
];

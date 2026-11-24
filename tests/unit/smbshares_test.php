<?php

declare(strict_types=1);

/**
 * Unit tests for the safe SMB share check's parsers (1.30): the NDR share list from hostile servers, and cleaning an
 * agent's results. No network.
 */

use Sentinel\Scanning\SmbShares;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'share list parser: types, cleaning, hostile counts and truncation' => function (TestContext $ctx): void {
        $str = static function (string $s): string {
            $u = (string) mb_convert_encoding($s . "\0", 'UTF-16LE', 'UTF-8');
            $n = intdiv(strlen($u), 2);
            $o = pack('VVV', $n, 0, $n) . $u;
            return $o . str_repeat("\0", (4 - strlen($o) % 4) % 4);
        };
        $stub = pack('VVVVVV', 1, 1, 0x20000, 3, 0x20004, 3) . pack('VVV', 1, 0, 0) . pack('VVV', 2, 0x80000003, 0) . pack('VVV', 3, 1, 0)
            . $str("Data\\..\x07") . $str('IPC$') . $str('Printer') . pack('VVV', 3, 0, 0);
        Assert::same([['name' => 'Data..', 'path' => 'Data..', 'type' => 'disk'], ['name' => 'IPC$', 'path' => 'IPC$', 'type' => 'ipc'], ['name' => 'Printer', 'path' => 'Printer', 'type' => 'printer']],
            SmbShares::parseShareEnum($stub), 'types read; backslashes and control characters removed');
        Assert::same(null, SmbShares::parseShareEnum(substr($stub, 0, 40)), 'truncated: refused');
        Assert::same(null, SmbShares::parseShareEnum(pack('VVVVVV', 1, 1, 0x20000, 4000000000, 0x20004, 4000000000)), 'absurd count: refused');
        Assert::same(null, SmbShares::parseShareEnum(pack('VVVVVV', 1, 1, 0x20000, 1, 0x20004, 1) . pack('VVV', 1, 0, 0) . pack('VVV', 999999, 0, 999999)), 'string longer than the data');
        Assert::same(null, SmbShares::parseShareEnum(pack('VV', 2, 2)), 'other levels refused');
        Assert::same(null, SmbShares::parseShareEnum(pack('V*', 1, 1, 0x20000, 0, 0, 0, 0, 5)), 'an empty answer with "access denied" is a refusal');
        Assert::same([], SmbShares::parseShareEnum(pack('V*', 1, 1, 0x20000, 0, 0, 0, 0, 0)), 'an empty list with success is empty');
        $long = str_repeat('L', 120);
        $one = pack('VVVVVV', 1, 1, 0x20000, 1, 0x20004, 1) . pack('VVV', 1, 0, 0) . $str($long) . pack('VVV', 1, 0, 0);
        $p = SmbShares::parseShareEnum($one);
        Assert::true(($p[0]['path'] ?? '') === $long && mb_strlen($p[0]['name'] ?? '') === 80, 'the whole name is kept for opening, 80 characters for evidence');
    },
    'share check: agent results cleaned to fixed values' => function (TestContext $ctx): void {
        $c = SmbShares::cleanResults(['session' => 'root', 'listed' => true, 'shares' => [
            ['name' => "Pub\\lic\n", 'type' => 'disk', 'readable' => true, 'items' => 999999999],
            ['name' => '', 'type' => 'disk', 'readable' => true],
            ['name' => 'X', 'type' => 'weird', 'readable' => 'yes', 'items' => 5],
            'junk',
        ]]);
        Assert::same('error', $c['session'], 'unknown session value');
        Assert::same(2, count($c['shares']));
        Assert::same(['name' => 'Public', 'type' => 'disk', 'readable' => true, 'items' => 100000, 'complete' => false], $c['shares'][0]);
        Assert::same(['name' => 'X', 'type' => 'other', 'readable' => null, 'items' => null, 'complete' => false], $c['shares'][1], 'no count unless readable');
    },
];

<?php

declare(strict_types=1);

/**
 * Unit tests for the default-credential checker's pure parts (1.29): masking, which services are tried, cleaning an
 * agent's results, the fixed list's rules and the SCRAM limits. No network.
 */

use Sentinel\Scanning\DefaultCredentials as DC;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'default credentials: masking, list rules, service matching' => function (TestContext $ctx): void {
        Assert::same('(blank)', DC::mask(''));
        Assert::same('••', DC::mask('ab'));
        Assert::same('a•••n', DC::mask('admin'));
        foreach (DC::LIST as $service => $pairs) {
            Assert::true(count($pairs) <= 3, $service . ': at most three attempts');
            Assert::same(count($pairs), count(array_unique(array_column($pairs, 0))), $service . ': each a different account');
        }
        Assert::same('mysql', DC::kindFor(3306, 'mysql', ''));
        Assert::same('elasticsearch', DC::kindFor(9200, 'http', 'Elasticsearch REST API'));
        Assert::same('http_basic', DC::kindFor(8081, 'http-proxy', ''));
        foreach ([[22, 'ssh'], [445, 'microsoft-ds'], [3389, 'ms-wbt-server'], [5985, 'wsman'], [389, 'ldap'], [88, 'kerberos-sec']] as [$port, $svc]) {
            Assert::same(null, DC::kindFor($port, $svc, ''), $svc . ' is never tried');
        }
    },
    'default credentials: agent results are cleaned to fixed values and masks' => function (TestContext $ctx): void {
        $clean = DC::cleanResults([
            ['port' => 21, 'service' => 'ftp', 'result' => 'login', 'user' => "root\x07", 'masked' => 'r••t', 'tried' => 2],
            ['port' => 3306, 'service' => 'mysql', 'result' => 'login', 'user' => 'root', 'masked' => 'TheRealPassword', 'tried' => 9],
            ['port' => 22, 'service' => 'ssh', 'result' => 'login', 'user' => 'root', 'masked' => 'x'],
            ['port' => 70000, 'service' => 'ftp', 'result' => 'login'],
            ['port' => 6379, 'service' => 'redis', 'result' => 'pwned'],
            ['port' => 5432, 'service' => 'postgresql', 'result' => 'denied', 'user' => 'postgres', 'masked' => 'p•••s'],
            'junk',
        ]);
        Assert::same(3, count($clean), 'unknown services, results and ports dropped');
        Assert::same('root', $clean[0]['user'], 'control characters removed');
        Assert::same('•••', $clean[1]['masked'], 'something that is not a mask is never kept');
        Assert::same(3, $clean[1]['tried'], 'attempts capped at three');
        Assert::same(['', ''], [$clean[2]['user'], $clean[2]['masked']], 'no username or mask unless a login worked');
    },
    'default credentials: SCRAM refuses hostile server values; MySQL scramble' => function (TestContext $ctx): void {
        Assert::same(null, DC::scramFinal('pw', 'n=,r=abc', 'abc', 'r=abcxyz,s=' . base64_encode('salt') . ',i=10000000'), 'iteration count capped');
        Assert::same(null, DC::scramFinal('pw', 'n=,r=abc', 'abc', 'r=other,s=' . base64_encode('salt') . ',i=4096'), 'nonce must extend ours');
        Assert::true(str_starts_with((string) DC::scramFinal('pw', 'n=,r=abc', 'abc', 'r=abcxyz,s=' . base64_encode('salt') . ',i=4096'), 'c=biws,r=abcxyz,p='), 'client-final message');
        Assert::same('', DC::mysqlScramble('mysql_native_password', '', str_repeat('s', 20)), 'blank password: empty answer');
        Assert::same(20, strlen(DC::mysqlScramble('mysql_native_password', 'pw', str_repeat('s', 20))));
        Assert::same(32, strlen(DC::mysqlScramble('caching_sha2_password', 'pw', str_repeat('s', 20))));
    },
];

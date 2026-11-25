<?php

declare(strict_types=1);

/**
 * Unit tests for internal-device rules: the software catalogue (only known
 * products, clean versions), Windows end-of-support dates by build and
 * edition, and device grading.
 */

use Sentinel\Inventory\DeviceRules;
use Sentinel\Inventory\OsLifecycle;
use Sentinel\Inventory\SoftwareCatalog;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'software catalog: anchored names, clean versions, nothing guessed' => function (TestContext $ctx): void {
        Assert::same(['product' => 'Google Chrome', 'cpe' => 'cpe:/a:google:chrome:120.0.6099.130'], SoftwareCatalog::identify('Google Chrome', '120.0.6099.130'));
        Assert::same('cpe:/a:mozilla:firefox:121.0', SoftwareCatalog::identify('Mozilla Firefox (x64 en-US)', '121.0')['cpe'] ?? null);
        Assert::same('cpe:/a:mozilla:firefox_esr:115.6.0', SoftwareCatalog::identify('Mozilla Firefox 115.6.0 ESR (x64 en-US)', '115.6.0')['cpe'] ?? null, 'ESR is its own product');
        Assert::same('cpe:/a:7-zip:7-zip:23.01', SoftwareCatalog::identify('7-Zip 23.01 (x64)', '')['cpe'] ?? null, 'version from the name');
        Assert::same('cpe:/a:notepad-plus-plus:notepad++:8.6.2', SoftwareCatalog::identify('Notepad++ (64-bit x64)', '8.6.2')['cpe'] ?? null);
        Assert::same('cpe:/a:python:python:3.12.1', SoftwareCatalog::identify('Python 3.12.1 (64-bit)', '3.12.1150.0')['cpe'] ?? null, 'Windows Python version decoded');
        Assert::same(null, SoftwareCatalog::identify('Python 3.12 (64-bit)', ''), 'no full Python version: not guessed');
        Assert::same('cpe:/a:putty:putty:0.80', SoftwareCatalog::identify('PuTTY release 0.80 (64-bit)', '0.80.0.0')['cpe'] ?? null, 'padding removed');
        Assert::same('cpe:/a:7-zip:7-zip:23.01', SoftwareCatalog::identify('7-Zip 23.01 (x64 edition)', '23.01.00.0')['cpe'] ?? null);
        foreach ([['Google Chrome Helper', '1.0'], ['Not Google Chrome', '120.0'], ['Microsoft Office Professional Plus 2019', '16.0.10827.20181'], ['Google Chrome', 'latest'], ['Example App', '1.0'],
                  ['Adobe Acrobat 2020', '20.005.30636'], ['Adobe Acrobat Reader 2017', '17.011.30204'], ['Microsoft Edge My', '120.0'], ['TeamViewer QS', '15.1']] as [$n, $v]) {
            Assert::same(null, SoftwareCatalog::identify($n, $v), 'not matched: ' . $n . ' ' . $v);
        }
        Assert::true(SoftwareCatalog::known('WinSCP 6.1.2') && !SoftwareCatalog::known('Example App'), 'catalog membership');
    },
    'Windows end of support by build and edition' => function (TestContext $ctx): void {
        Assert::same('2025-10-14', OsLifecycle::endOfSupport('Windows 10 Professional Edition', '19045'));
        Assert::same('2024-06-11', OsLifecycle::endOfSupport('Windows 10 Enterprise', '10.0.19044'), 'Enterprise lasts longer');
        Assert::same('2027-01-12', OsLifecycle::endOfSupport('Windows 10 Enterprise LTSC 2021', '19044'), 'LTSC');
        Assert::same('2023-10-10', OsLifecycle::endOfSupport('Windows 11 Pro', '22000'));
        Assert::same('2023-10-10', OsLifecycle::endOfSupport('Windows Server 2012 R2 Standard', '9600'), 'server table');
        Assert::same('2023-01-10', OsLifecycle::endOfSupport('Windows 8.1 Pro', '9600'), 'same build, client table');
        Assert::same('2029-01-09', OsLifecycle::endOfSupport('Windows Server 2019 Datacenter', '17763'));
        Assert::same(null, OsLifecycle::endOfSupport('macOS Sonoma', '23.2'), 'not judged');
        Assert::same('2032-01-13', OsLifecycle::endOfSupport('Windows 10 IoT Enterprise LTSC 2021', '19044'), 'IoT LTSC lasts longer');
        Assert::same('2023-06-13', OsLifecycle::endOfSupport('Windows 10 Pro Education', '19044'), 'Pro Education follows Home/Pro');
        Assert::same(null, OsLifecycle::endOfSupport('Windows 11 Pro', '99999'), 'unknown build: not judged');
    },
    'device grading' => function (TestContext $ctx): void {
        $now = strtotime('2027-06-01 12:00:00 UTC');
        $base = ['os_name' => 'Windows 11 Enterprise', 'os_build' => '26200', 'av_state' => 'on', 'av_product' => 'X', 'av_definitions' => 'current', 'encryption' => 'on',
                 'device_class' => 'workstation', 'last_contact' => '2027-06-01 10:00:00'];
        $codes = static fn (array $d, array $p = []): array => array_column(DeviceRules::issues($d, $p, $now), 'severity', 'code');
        Assert::same([], $codes($base), 'healthy');
        Assert::same(['os_unsupported' => 'fail'], $codes(['os_name' => 'Windows 10 Pro', 'os_build' => '19045'] + $base));
        Assert::same(['av_missing' => 'fail'], $codes(['av_state' => 'missing'] + $base));
        Assert::same(['av_outdated' => 'warn'], $codes(['av_definitions' => 'outdated'] + $base));
        Assert::same(['encryption_off' => 'warn'], $codes(['encryption' => 'off'] + $base));
        Assert::same(['encryption_off_server' => 'info'], $codes(['encryption' => 'off', 'device_class' => 'server'] + $base));
        Assert::same(['stale' => 'info'], $codes(['last_contact' => '2027-04-01 10:00:00'] + $base));
        $patches = [['status' => 'pending', 'severity' => 'Critical', 'detected_at' => '2027-04-01 00:00:00', 'kb' => 'KB1', 'name' => 'a'],
                    ['status' => 'pending', 'severity' => 'critical', 'detected_at' => '2027-05-30 00:00:00', 'kb' => 'KB2', 'name' => 'b'],
                    ['status' => 'pending', 'severity' => 'optional', 'detected_at' => '2027-01-01 00:00:00', 'kb' => 'KB3', 'name' => 'c']];
        Assert::same(['patches_missing' => 'warn'], $codes($base, $patches), 'only security updates older than 30 days');
        Assert::same('patch', DeviceRules::type('patches_failed'));
    },
    'source text is cleaned: bad bytes, controls, invisible characters, non-text' => function (TestContext $ctx): void {
        $clean = [\Sentinel\Inventory\InventoryRepository::class, 'clean'];
        Assert::same('Bad ? byte', str_replace("\u{FFFD}", '?', $clean("Bad \xC3 byte", 50)), 'invalid UTF-8 kept, bad byte replaced');
        Assert::same('evil exe', $clean("evil\u{202E}exe", 50), 'direction override removed');
        Assert::same('a b', $clean("a\x07\u{0085}b", 50), 'C0 and C1 controls removed');
        Assert::same('', $clean(['array'], 50), 'non-text value');
    },
    'routes reject parameter names that could never match' => function (TestContext $ctx): void {
        $router = new \Sentinel\Core\Router();
        $router->add('GET', '/clients/{id}/devices/{device}', [\stdClass::class, 'x']);
        $threw = false;
        try {
            $router->add('GET', '/x/{deviceId}', [\stdClass::class, 'x']);
        } catch (\InvalidArgumentException) {
            $threw = true;
        }
        Assert::true($threw, 'unknown parameter form refused');
    },
];

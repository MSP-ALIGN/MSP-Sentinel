<?php

declare(strict_types=1);

/**
 * Tests for packaging: the release archive (contents, no tests or config,
 * reproducible), the installer's dry run (no secrets printed, every step
 * shown), the templates, and bin/setup-config.php. Nothing is installed.
 */

use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'release archive: committed files only, no tests or config, reproducible' => function (TestContext $ctx): void {
        $root = dirname(__DIR__, 2);
        $out = sys_get_temp_dir() . '/sentinel-dist-' . bin2hex(random_bytes(4));
        exec('bash ' . escapeshellarg($root . '/bin/build-release.sh') . ' --allow-dirty --out ' . escapeshellarg($out) . ' 2>&1', $lines, $code);
        Assert::same(0, $code, implode("\n", $lines));
        $version = trim((string) file_get_contents($root . '/VERSION'));
        $tar = $out . '/msp-sentinel-' . $version . '.tar.gz';
        Assert::true(is_file($tar), 'archive built');
        $first = hash_file('sha256', $tar);
        Assert::contains($first, (string) file_get_contents($out . '/SHA256SUMS'));
        exec('tar -tzf ' . escapeshellarg($tar), $names);
        $prefix = 'msp-sentinel-' . $version . '/';
        Assert::true(in_array($prefix . 'VERSION', $names, true) && in_array($prefix . 'public/index.php', $names, true), 'app files included');
        foreach ($names as $n) {
            Assert::true(!str_starts_with($n, $prefix . 'tests/') && $n !== $prefix . 'config/config.php' && !str_starts_with($n, $prefix . 'storage/')
                && $n !== $prefix . 'bin/build-release.sh' && !str_ends_with($n, '.bundle'), 'not in a release: ' . $n);
        }
        exec('bash ' . escapeshellarg($root . '/bin/build-release.sh') . ' --allow-dirty --out ' . escapeshellarg($out) . ' 2>&1');
        Assert::same($first, hash_file('sha256', $tar), 'same commit, same bytes');
        array_map('unlink', glob($out . '/*') ?: []);
        rmdir($out);
    },
    'one-line installer: asks or reads settings, refuses bad input, hands over to the installer' => function (TestContext $ctx): void {
        $root = dirname(__DIR__, 2);
        $env = 'SENTINEL_DRY_RUN=1 SENTINEL_FORCE=1 SENTINEL_SRC=' . escapeshellarg($root) . ' ';
        exec($env . 'SENTINEL_DOMAIN=Sentinel.Example bash ' . escapeshellarg($root . '/install.sh') . ' </dev/null 2>&1', $lines, $rc);
        $out = implode("\n", $lines);
        Assert::same(0, $rc, $out);
        foreach (['Installing MSP Sentinel for https://sentinel.example', 'msp-sentinel-update', 'php8.4-fpm', 'migrate.php', 'nginx -t'] as $step) {
            Assert::contains($step, $out);
        }
        exec($env . 'SENTINEL_DOMAIN=sentinel.example SENTINEL_TLS=letsencrypt SENTINEL_LE_EMAIL=ops@msp.example bash ' . escapeshellarg($root . '/install.sh') . ' </dev/null 2>&1', $l2, $rc2);
        Assert::same(0, $rc2, implode("\n", $l2));
        Assert::contains('certbot certonly', implode("\n", $l2), 'Let\'s Encrypt chosen');
        // Behind a reverse proxy: plain HTTP for the proxy only, firewall opened for it only, trusted in the config.
        exec($env . 'SENTINEL_DOMAIN=sentinel.example SENTINEL_TLS=proxy SENTINEL_PROXY_IP=192.0.2.10 SENTINEL_BACKUP_PASSPHRASE=a-long-test-passphrase bash ' . escapeshellarg($root . '/install.sh') . ' </dev/null 2>&1', $l3, $rc3);
        $proxy = implode("\n", $l3);
        Assert::same(0, $rc3, $proxy);
        foreach (['Nginx behind the reverse proxy (192.0.2.10)', 'ufw allow from 192.0.2.10 to any port 80', '--trusted-proxy=192.0.2.10', 'Encrypted backups', 'fail2ban', 'unattended-upgrades'] as $step) {
            Assert::contains($step, $proxy);
        }
        Assert::notContains('certbot', $proxy);
        Assert::notContains('a-long-test-passphrase', $proxy, 'the passphrase is never printed');
        Assert::notContains('ufw allow 443', $proxy, 'no public HTTPS port in proxy mode');
        Assert::contains('remove earlier MSP Sentinel web rules', $proxy, 'stale web rules are cleaned up');
        exec($env . 'SENTINEL_DOMAIN=sentinel.example SENTINEL_FIREWALL=n SENTINEL_FAIL2BAN=no SENTINEL_AUTO_UPDATES=0 bash ' . escapeshellarg($root . '/install.sh') . ' </dev/null 2>&1', $l4, $rc4);
        $off = implode("\n", $l4);
        Assert::same(0, $rc4, $off);
        Assert::true(!str_contains($off, 'ufw') && !str_contains($off, 'fail2ban') && !str_contains($off, 'unattended'), 'optional steps left out');
        $tpl = (string) file_get_contents($root . '/install/templates/nginx-proxy.conf');
        Assert::true(str_contains($tpl, 'allow __PROXY__;') && str_contains($tpl, 'deny all;') && !str_contains($tpl, 'fastcgi_param HTTPS on'), 'proxy site accepts the proxy only');
        $inst = (string) file_get_contents($root . '/install/install.sh');
        Assert::contains('render nginx-proxy.conf', $inst, 'proxy site goes through render (drops [::] lines without IPv6)');
        Assert::notContains('%q', $inst, 'backup.env uses POSIX quoting that sh can read');
        foreach ([['SENTINEL_DOMAIN="bad domain;rm"', 'bad host name'], ['SENTINEL_DOMAIN=sentinel.example SENTINEL_TLS=other', 'bad TLS mode'],
                  ['SENTINEL_DOMAIN=sentinel.example SENTINEL_TLS=proxy SENTINEL_PROXY_IP="1.2.3.4;rm"', 'bad proxy address'],
                  ['SENTINEL_DOMAIN=sentinel.example SENTINEL_TLS=proxy SENTINEL_PROXY_IP=300.1.1.1', 'impossible IPv4'],
                  ['SENTINEL_DOMAIN=sentinel.example SENTINEL_BACKUP_PASSPHRASE=short', 'short passphrase'],
                  ['SENTINEL_DOMAIN=sentinel.example SENTINEL_TLS=proxy SENTINEL_PROXY_IP=010.0.0.1', 'leading zeros'],
                  ['SENTINEL_DOMAIN=sentinel.example SENTINEL_TLS=proxy SENTINEL_PROXY_IP=:::::', 'colons only'],
                  ['SENTINEL_DOMAIN=sentinel.example SENTINEL_TLS=proxy SENTINEL_PROXY_IP=1::2::3', 'two ::'],
                  ['SENTINEL_DOMAIN=sentinel.example SENTINEL_FIREWALL=maybe', 'yes/no must be y or n'],
                  ['SENTINEL_DOMAIN=sentinel.example SENTINEL_BRANCH="../x"', 'bad branch'], ['SENTINEL_DOMAIN=sentinel.example SENTINEL_REPO="a/b c"', 'bad repository'],
                  ['', 'no host name and no terminal']] as [$vars, $why]) {
            exec($env . $vars . ' bash ' . escapeshellarg($root . '/install.sh') . ' </dev/null 2>&1', $l, $c);
            Assert::true($c !== 0, $why);
        }
        // Development server: the same wizard, following develop, marked as a development build.
        exec($env . 'SENTINEL_DOMAIN=dev.msp.example bash ' . escapeshellarg($root . '/install-dev.sh') . ' </dev/null 2>&1', $l5, $rc5);
        $dev = implode("\n", $l5);
        Assert::same(0, $rc5, $dev);
        foreach (['branch develop', 'Development build', 'follows MSP-ALIGN/MSP-Sentinel, branch develop', 'https://dev.msp.example'] as $step) {
            Assert::contains($step, $dev);
        }
        Assert::notContains('Development build', implode("\n", $lines), 'main installs are not marked');
        $boot = (string) file_get_contents($root . '/install.sh');
        Assert::true(str_contains($boot, 'SENTINEL_SWITCH_BRANCH') && strpos($boot, 'SENTINEL_SWITCH_BRANCH') < strpos($boot, 'log "Fetching MSP Sentinel'), 'branch switch is confirmed before anything is fetched');
        Assert::true((bool) preg_match('/bash "\$SRC_DIR\/install\/install.sh" "\$\{args\[@\]\}"\n\s*install_update_command/', $boot), 'update.env is rewritten only after a successful upgrade');
        Assert::contains('[ -f "$SRC/BUILD" ] || run rm -f "$APP_DIR/BUILD"', (string) file_get_contents($root . '/install/install.sh'), 'stale build stamp removed');
        exec($env . 'SENTINEL_BRANCH="x;rm" bash ' . escapeshellarg($root . '/install-dev.sh') . ' </dev/null 2>&1', $l6, $rc6);
        Assert::true($rc6 !== 0, 'bad branch refused before any download');
        foreach (['install.sh', 'install-agent.sh', 'install-dev.sh'] as $f) {
            exec('bash -n ' . escapeshellarg($root . '/' . $f) . ' 2>&1', $l, $c);
            Assert::same(0, $c, $f . ' syntax');
        }
        Assert::contains('debian-13', (string) file_get_contents($root . '/install/install.sh'), 'Debian 13 supported');
    },
    'agent installer: dry run, input checks, hardened unprivileged service' => function (TestContext $ctx): void {
        $root = dirname(__DIR__, 2);
        $code = 'SNE-ABCDE-FGHJK-LMNPQ-RSTUV';
        exec('bash ' . escapeshellarg($root . '/install/agent-install.sh') . ' --dry-run --skip-os-check --server https://sentinel.example --code ' . $code . ' 2>&1', $lines, $rc);
        $out = implode("\n", $lines);
        Assert::same(0, $rc, $out);
        foreach (['php8.4-cli', 'nmap', 'useradd --system', 'runuser -u sentinel-agent', 'sentinel-agent.php enrol', 'systemctl enable --now sentinel-agent'] as $step) {
            Assert::contains($step, $out);
        }
        Assert::notContains('LXC container detected', $out, 'a machine or VM gets no container step');
        // In an LXC container (Proxmox, 1.36): the sandbox is probed and relaxed only if it can't start.
        exec('SENTINEL_FORCE_VIRT=lxc bash ' . escapeshellarg($root . '/install/agent-install.sh') . ' --dry-run --skip-os-check --server https://sentinel.example --code ' . $code . ' 2>&1', $lxc, $lxcRc);
        $lxcOut = implode("\n", $lxc);
        Assert::same(0, $lxcRc, $lxcOut);
        Assert::contains('LXC container detected', $lxcOut);
        Assert::contains('probe systemd sandboxing', $lxcOut);
        Assert::true(strpos($lxcOut, 'probe systemd sandboxing') < strpos($lxcOut, 'systemctl enable --now sentinel-agent'), 'probed before the service starts');
        // Every option of the agent's unit that needs a mount namespace is probed and relaxed together (1.36.1).
        $installer = (string) file_get_contents($root . '/install/agent-install.sh');
        $unitText = (string) file_get_contents($root . '/install/templates/sentinel-agent.service');
        foreach (['ProtectSystem', 'ProtectHome', 'PrivateTmp', 'PrivateDevices', 'ProtectKernelTunables', 'ProtectKernelModules', 'ProtectKernelLogs', 'ProtectControlGroups', 'ProtectProc', 'ProtectHostname', 'ProtectClock'] as $opt) {
            if (preg_match('/^' . $opt . '=/m', $unitText) === 1) {
                Assert::contains('-p ' . $opt . '=', $installer, 'probed: ' . $opt);
                Assert::true(preg_match("/'" . $opt . "=(no|default)'/", $installer) === 1, 'relaxed: ' . $opt);
            }
        }
        foreach ([['--server http://sentinel.example --code ' . $code, 'plain http refused'], ['--server "https://x.example/;rm" --code ' . $code, 'odd server value refused'],
                  ['--server https://sentinel.example --code bad', 'bad code refused']] as [$args, $why]) {
            exec('bash ' . escapeshellarg($root . '/install/agent-install.sh') . ' --dry-run --skip-os-check ' . $args . ' 2>&1', $l, $c);
            Assert::same(1, $c, $why);
        }
        $unit = (string) file_get_contents($root . '/install/templates/sentinel-agent.service');
        foreach (['User=sentinel-agent', 'NoNewPrivileges=yes', 'ProtectSystem=strict', 'RestartPreventExitStatus=3'] as $line) {
            Assert::contains($line, $unit);
        }
        // One capability only (listening on UDP 137 for NetBIOS name requests); never raw sockets or anything else.
        Assert::contains("\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n", $unit);
        Assert::contains("\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n", $unit);
        Assert::notContains('CAP_NET_RAW', $unit);
    },
    'installer dry run shows every step and never a secret' => function (TestContext $ctx): void {
        $root = dirname(__DIR__, 2);
        exec('bash ' . escapeshellarg($root . '/install/install.sh') . ' --dry-run --skip-os-check --domain sentinel.example 2>&1', $lines, $code);
        $out = implode("\n", $lines);
        Assert::same(0, $code, $out);
        foreach (['php8.4-fpm', 'useradd --system', 'create database msp_sentinel', 'setup-config.php', 'migrate.php', 'pool.d/msp-sentinel.conf',
                  'sites-available/msp-sentinel', 'nginx -t', '/etc/cron.d/msp-sentinel', 'doctor.php'] as $step) {
            Assert::contains($step, $out);
        }
        Assert::notContains('IDENTIFIED BY', $out, 'database password never printed');
        foreach (['chmod o+x /opt/msp-sentinel /opt/msp-sentinel/public', 'chmod -R o+rX /opt/msp-sentinel/public/assets'] as $step) {
            Assert::contains($step, $out, 'Nginx can read the static files');
        }
        exec('bash ' . escapeshellarg($root . '/install/install.sh') . ' --dry-run --skip-os-check --upgrade 2>&1', $lu, $codeU);
        $up = implode("\n", $lu);
        Assert::same(0, $codeU, $up);
        Assert::true(strpos($up, 'cron.paused') < strpos($up, 'backup.php') && strpos($up, 'backup.php') < strpos($up, 'rsync -a --delete'), 'jobs stopped, then backup, then code');
        Assert::contains('backup.env', $up, 'pre-upgrade backup honours encryption settings');
        exec('bash ' . escapeshellarg($root . '/install/install.sh') . ' --dry-run --skip-os-check --domain "bad domain;rm" 2>&1', $l2, $code2);
        Assert::same(1, $code2, 'invalid domain refused');
        exec('bash ' . escapeshellarg($root . '/install/install.sh') . ' --dry-run --skip-os-check --domain sentinel.example --certbot 2>&1', $l3, $code3);
        Assert::same(1, $code3, 'certbot needs an email');
        // Templates: every placeholder is one the installer fills.
        foreach (glob($root . '/install/templates/*') ?: [] as $t) {
            preg_match_all('/__([A-Z]+)__/', (string) file_get_contents($t), $m);
            Assert::same([], array_diff(array_unique($m[1]), ['DOMAIN', 'ROOT', 'CERT', 'KEY', 'PHP', 'CONF', 'PROXY']), basename($t));
        }
        Assert::contains('fastcgi_param HTTP_AUTHORIZATION', (string) file_get_contents($root . '/install/templates/nginx.conf'));
        Assert::notContains(' root ', (string) preg_replace('/^#.*$/m', '', (string) file_get_contents($root . '/install/templates/cron')), 'no cron job runs as root');
    },
    'web update runner: removes the request without reading it, runs the fixed command, reports progress' => function (TestContext $ctx): void {
        $root = dirname(__DIR__, 2);
        $dir = sys_get_temp_dir() . '/sentinel-runner-' . bin2hex(random_bytes(4));
        mkdir($dir . '/state', 0750, true);
        mkdir($dir . '/storage');
        // The template with its fixed paths pointed into the sandbox (and no "sentinel" group needed).
        $script = strtr((string) file_get_contents($root . '/install/templates/msp-sentinel-update-runner'), [
            'STATE=/var/lib/msp-sentinel-update' => 'STATE=' . $dir . '/state', '__ROOT__' => $dir, '/usr/local/sbin/msp-sentinel-update' => $dir . '/fake-update',
            'chgrp sentinel' => 'true']);
        file_put_contents($dir . '/runner', $script);
        $run = static function () use ($dir): void {
            exec('bash ' . escapeshellarg($dir . '/runner') . ' 2>&1', $o, $c);
        };
        $status = static fn (): array => json_decode((string) @file_get_contents($dir . '/state/status.json'), true) ?: [];
        file_put_contents($dir . '/fake-update', "#!/bin/sh\necho \"updating \$*\"\nexit 0\n");
        chmod($dir . '/fake-update', 0755);

        // Turned off (no "enabled" marker): the request is removed and nothing runs.
        touch($dir . '/storage/update-request');
        $run();
        Assert::true(!file_exists($dir . '/storage/update-request') && $status() === [], 'off: nothing runs');

        // A request that is a symlink to a file root must not touch: only the link is removed.
        touch($dir . '/state/enabled');
        file_put_contents($dir . '/precious', 'keep me');
        symlink($dir . '/precious', $dir . '/storage/update-request');
        $run();
        Assert::same('keep me', file_get_contents($dir . '/precious'), 'symlink target untouched');
        Assert::true(!is_link($dir . '/storage/update-request'), 'link removed');
        Assert::same(['done', 0], [$status()['state'] ?? '', $status()['exit'] ?? -1]);
        Assert::contains('updating', (string) file_get_contents($dir . '/state/update.log'), 'output logged');
        Assert::notContains('keep me', (string) file_get_contents($dir . '/state/update.log'), 'the request is never read');

        // At most one start every 15 minutes, whoever creates the request file.
        $started = $status()['started'] ?? '';
        touch($dir . '/storage/update-request');
        $run();
        Assert::same($started, $status()['started'] ?? '', 'a second request within 15 minutes does not run');
        Assert::contains('less than 15 minutes ago', (string) file_get_contents($dir . '/state/update.log'));
        // A directory at the request path is removed too (else the path unit would start the runner again and again).
        $old = static function () use ($dir, $status): void {
            file_put_contents($dir . '/state/status.json', json_encode(['started' => gmdate('Y-m-d H:i:s', time() - 3600)] + $status()));
        };
        $old();
        mkdir($dir . '/storage/update-request');
        touch($dir . '/storage/update-request/x');
        file_put_contents($dir . '/fake-update', "#!/bin/sh\necho boom\nexit 3\n");
        $run();
        Assert::true(!file_exists($dir . '/storage/update-request'), 'directory removed');
        // A failing update is reported with its exit code.
        Assert::same(['failed', 3], [$status()['state'] ?? '', $status()['exit'] ?? -1]);
        // The units point at the runner and the request file.
        $unit = (string) file_get_contents($root . '/install/templates/msp-sentinel-web-update.path');
        Assert::true(str_contains($unit, 'PathExists=__ROOT__/storage/update-request') && !preg_match('/^TriggerLimit/m', $unit), 'path unit without a strict trigger limit (it switched the unit off)');
        $inst = (string) file_get_contents($root . '/install/install.sh');
        Assert::true(str_contains($inst, 'systemctl reset-failed msp-sentinel-web-update.path') && !str_contains($inst, 'run systemctl enable --now msp-sentinel-web-update.path'), 'a stuck unit never stops an upgrade');
        Assert::contains('ExecStart=/usr/local/sbin/msp-sentinel-update-runner', (string) file_get_contents($root . '/install/templates/msp-sentinel-web-update.service'));
        exec('rm -rf ' . escapeshellarg($dir));
    },
    'setup-config writes a valid private config and never overwrites one' => function (TestContext $ctx): void {
        $root = dirname(__DIR__, 2);
        $path = sys_get_temp_dir() . '/sentinel-setup-' . bin2hex(random_bytes(4)) . '.php';
        $run = static function (array $args, string $stdin) use ($root): array {
            $p = proc_open(array_merge([PHP_BINARY, $root . '/bin/setup-config.php'], $args), [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            fwrite($pipes[0], $stdin);
            fclose($pipes[0]);
            $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
            return [proc_close($p), $out];
        };
        [$code, $out] = $run(['--public-url=https://sentinel.example', '--config=' . $path], "Db-Pass-Example-123\n");
        Assert::same(0, $code, $out);
        Assert::same('0640', substr(sprintf('%o', fileperms($path)), -4));
        $cfg = require $path;
        Assert::same(32, strlen((string) base64_decode($cfg['app_key'], true)), 'fresh 32-byte app key');
        Assert::same(['Db-Pass-Example-123', 'https://sentinel.example', true], [$cfg['db']['pass'], $cfg['app']['public_url'], $cfg['app']['force_secure_cookies']]);
        [$code] = $run(['--public-url=https://sentinel.example', '--config=' . $path], "x\n");
        Assert::same(1, $code, 'refuses to overwrite (the app key would be lost)');
        [$code] = $run(['--public-url=http://sentinel.example', '--config=' . $path . '2'], "x\n");
        Assert::same(2, $code, 'https only');
        // --update (installer re-run in proxy mode): only the trusted proxy changes; the app key is kept.
        $before = require $path;
        [$code, $out] = $run(['--update', '--trusted-proxy=2001:DB8::10', '--config=' . $path], '');
        Assert::same(0, $code, $out);
        clearstatcache();
        $after = require $path;
        Assert::same([$before['app_key'], $before['db']['pass'], ['2001:db8::10']], [$after['app_key'], $after['db']['pass'], $after['app']['trusted_proxies']]);
        Assert::same('0640', substr(sprintf('%o', fileperms($path)), -4), 'permissions kept');
        [$code] = $run(['--update', '--trusted-proxy=not-an-ip', '--config=' . $path], '');
        Assert::same(2, $code, 'bad proxy address refused');
        [$code] = $run(['--update', '--trusted-proxy=192.0.2.10', '--config=' . $path . '.missing'], '');
        Assert::same(2, $code, 'no config to update');
        unlink($path);
    },
    'agent units repair an update stopped half-way, before anything runs from the code folder' => function (TestContext $ctx): void {
        $root = dirname(__DIR__, 2);
        foreach (['sentinel-agent.service', 'sentinel-agent-update.service'] as $unitName) {
            $unit = (string) file_get_contents($root . '/install/templates/' . $unitName);
            Assert::true(preg_match("/^ExecStartPre=\\+\\/bin\\/sh -c '(.+)'$/m", $unit, $m) === 1, $unitName . ' has the root repair step');
            Assert::true(strpos($unit, 'ExecStartPre=+/bin/sh') < strpos($unit, "\nExecStart="), $unitName . ': repair comes before the code runs');
            // Run the step itself on test folders (the same shell line, with the code folder pointed at a temp folder).
            $base = sys_get_temp_dir() . '/sn-repair-' . bin2hex(random_bytes(4));
            mkdir($base);
            $app = $base . '/sentinel-agent';
            $runStep = static function () use ($m, $app): void {
                exec('/bin/sh -c ' . escapeshellarg(str_replace('__ROOT__', $app, $m[1])) . ' 2>&1', $o, $rc);
                Assert::same(0, $rc, implode("\n", $o));
            };
            // 1. Stopped between the two renames: only the previous version is there. It is put back.
            mkdir($app . '.old');
            file_put_contents($app . '.old/VERSION', "1.0.0\n");
            $runStep();
            Assert::true(is_file($app . '/VERSION') && !file_exists($app . '.old'), $unitName . ': previous version put back');
            // 2. A normal state (code folder and an older copy): nothing changes.
            mkdir($app . '.old');
            $runStep();
            Assert::true(is_dir($app) && is_dir($app . '.old') && !is_dir($app . '/sentinel-agent.old'), $unitName . ': nothing moved when the code is there');
            // 3. A symlink in place of the previous version is never followed or moved.
            exec('rm -rf ' . escapeshellarg($app) . ' ' . escapeshellarg($app . '.old'));
            mkdir($base . '/elsewhere');
            symlink($base . '/elsewhere', $app . '.old');
            $runStep();
            Assert::true(!file_exists($app) && is_link($app . '.old'), $unitName . ': a symlink is left alone');
            // 4. Nothing at all: nothing happens, no error.
            unlink($app . '.old');
            $runStep();
            Assert::true(!file_exists($app), $unitName . ": nothing created");
            exec('rm -rf ' . escapeshellarg($base));
        }
    },
    'Proxmox helper: unprivileged Debian 13 container with nesting, strict input checks, no enrolment code' => function (TestContext $ctx): void {
        $script = escapeshellarg(dirname(__DIR__, 2) . '/install/proxmox-agent-ct.sh');
        exec('bash ' . $script . ' --dry-run --bridge vmbr1 --vlan 20 --ip 10.0.20.50/24 --gw 10.0.20.1 --ctid 120 2>&1', $l, $rc);
        $out = implode("\n", $l);
        Assert::same(0, $rc, $out);
        foreach (['pct create 120', '--unprivileged 1', '--features nesting=1', 'bridge=vmbr1,ip=10.0.20.50/24,gw=10.0.20.1,tag=20', '--onboot 1', 'pct start 120', 'pct enter 120'] as $needle) {
            Assert::contains($needle, $out);
        }
        Assert::notContains('--code', $out, 'the enrolment code is never passed on the host');
        foreach (["--bridge 'vmbr0;rm'", '--bridge vmbr0 --vlan 5000', '--bridge vmbr0 --ctid 12', '--bridge vmbr0 --ip 10.0.0.5', "--bridge vmbr0 --hostname 'a b'", '--bridge vmbr0 --memory 64', "--bridge vmbr0 --gw '1.2.3.4,bridge=vmbr9'", '--bridge vmbr0 --ip 999.1.1.1/24 --gw 10.0.0.1', ''] as $bad) {
            exec('bash ' . $script . ' --dry-run ' . $bad . ' 2>&1', $o, $c);
            Assert::true($c !== 0, 'refused: ' . ($bad === '' ? '(no bridge)' : $bad));
            $o = [];
        }
    },
];

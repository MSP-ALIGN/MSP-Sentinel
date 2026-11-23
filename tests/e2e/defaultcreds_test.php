<?php

declare(strict_types=1);

/**
 * End-to-end tests for the default-credential engagement test (1.29): only with the explicit authorisation tick; at
 * most three attempts per service, each a different account, spaced; stops at a lockout; the password is only ever
 * stored masked; databases open without a password; externally from Sentinel and internally through the agent (which
 * needs 1.29.1). Fake login servers on 127.0.0.1 only; made-up data and documentation ranges.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$dcSetup = static function (TestContext $ctx): array {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Default Creds Example'")->fetchColumn();
    if ($cid === 0) {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Default Creds Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $admin->submit('/clients/' . $cid . '/authorisations/new', '/clients/' . $cid . '/authorisations', [
            'approved_by_name' => 'Robin Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'),
            'valid_from' => gmdate('Y-m-d', time() - 86400), 'valid_until' => gmdate('Y-m-d', time() + 86400 * 200),
            'document_ref' => '', 'notes' => '', 'scope' => "203.0.113.72/30\n", 'confirm' => '1']);
        $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
        $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
            'approved_by_name' => 'Sam Example', 'approved_by_role' => 'IT Manager', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
            'valid_until' => gmdate('Y-m-d', time() + 86400 * 300), 'document_ref' => 'TICKET-4001', 'notes' => '', 'ranges' => '10.89.0.0/24', 'confirm' => '1']);
        foreach (['dctech' => 'technician', 'dcadmin2' => 'admin'] as $u => $role) {
            if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = '{$u}'")->fetchColumn() === 0) {
                $ctx->createUser($u, $role, ucfirst($u) . '-Pass-0001!');
            }
        }
    }
    $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
    $pdf = dirname($ctx->configPath) . '/signed-authorisation.pdf';
    file_put_contents($pdf, "%PDF-1.4\n% made-up signed authorisation for the test suite\n%%EOF\n");
    return [$cid, $site, $pdf];
};
$dcFields = static fn (int $site, array $over = []): array => $over + [
    'name' => 'Default password test', 'signer_name' => 'Robin Example', 'signer_role' => 'Owner', 'signed_on' => gmdate('Y-m-d'),
    'window_start' => gmdate('Y-m-d\TH:i', time() - 3600), 'window_end' => gmdate('Y-m-d\TH:i', time() + 86400), 'intensity' => 'normal',
    'tests[0]' => 'default_creds', 'tests[1]' => 'tcp_full', 'external' => '203.0.113.72/30', 'internal_' . $site => '', 'exclusions' => '', 'notes' => '', 'confirm' => '1', 'creds_confirm' => '1',
];
$dcLast = static fn (TestContext $ctx, int $cid): int => (int) $ctx->db->query("SELECT MAX(id) FROM engagements WHERE client_id = {$cid}")->fetchColumn();
$attempts = static fn (TestContext $ctx): array => array_values(array_filter(array_map(static fn (string $l): array => explode(' ', $l, 3),
    is_file(dirname($ctx->nmapLog) . '/creds-attempts.log') ? (file(dirname($ctx->nmapLog) . '/creds-attempts.log', FILE_IGNORE_NEW_LINES) ?: []) : [])));

return [
    'default passwords: only with the explicit authorisation tick' => function (TestContext $ctx) use ($dcSetup, $dcFields, $dcLast): void {
        [$cid, $site, $pdf] = $dcSetup($ctx);
        $tech = $ctx->login('dctech', 'Dctech-Pass-0001!');
        $before = $dcLast($ctx, $cid);
        $res = $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $dcFields($site, ['creds_confirm' => '']), 'document', $pdf, 'application/pdf');
        Assert::status(422, $res);
        Assert::contains('explicitly allows trying vendor default passwords', $res->body);
        Assert::same($before, $dcLast($ctx, $cid), 'not created without the tick');
    },
    'default passwords externally: no username twice on a host, spaced, masked evidence, Windows sign-in never tried' => function (TestContext $ctx) use ($dcSetup, $dcFields, $dcLast, $attempts): void {
        [$cid, $site, $pdf] = $dcSetup($ctx);
        $tech = $ctx->login('dctech', 'Dctech-Pass-0001!');
        $admin2 = $ctx->login('dcadmin2', 'Dcadmin2-Pass-0001!');
        $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $dcFields($site), 'document', $pdf, 'application/pdf');
        $id = $dcLast($ctx, $cid);
        $admin2->post('/engagements/' . $id . '/approve', ['_csrf' => $admin2->get('/engagements/' . $id)->csrf(), 'password' => 'Dcadmin2-Pass-0001!']);
        $runExternal = static function (int $eid) use ($ctx, $tech): void {
            $tech->post('/engagements/' . $eid . '/run-external', ['_csrf' => $tech->get('/engagements/' . $eid)->csrf()]);
            $jobs = App::engagements()->externalJobs($eid);
            [$code, $out] = $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . (int) $jobs[0]['id']]);
            Assert::same(0, $code, 'worker: ' . $out);
        };
        @unlink(dirname($ctx->nmapLog) . '/creds-attempts.log');
        $runExternal($id);
        $by = [];
        $times = [];
        foreach ($attempts($ctx) as [$t, $mode, $user]) {
            $by[$mode][] = $user;
            $times[] = (float) $t;
        }
        // Host .72: FTP and the web admin page share the host, so each username is tried once on it, whatever the port.
        Assert::same(['admin', 'root'], $by['ftp'] ?? [], 'FTP: stops at the first success (second account)');
        Assert::same(['ubnt'], $by['http-basic'] ?? [], 'web page: only the account not yet tried on this host');
        // Host .73: MySQL root with a blank password, first try; then PostgreSQL's own default.
        Assert::same(['root'], $by['mysql-native'] ?? [], 'MySQL: root with a blank password, first try');
        Assert::same(['postgres'], $by['pg-md5'] ?? []);
        // Host .74: no default works: three DIFFERENT accounts, never more. Windows sign-in is never tried.
        Assert::same(['root', 'admin', 'mysql'], $by['mysql-sha2'] ?? [], 'three different accounts, never more');
        Assert::true(!isset($by['http-ntlm']), 'a page offering Negotiate/NTLM (Windows accounts) is never tried');
        sort($times);
        Assert::true(count($times) >= 6, 'attempts made');
        $results = App::engagements()->results($id);
        $byIp = array_column($results, null, 'ip');
        $creds = static fn (string $ip): array => array_column((array) ($byIp[$ip]['checks_list']['creds'] ?? []), null, 'port');
        Assert::same('denied', $creds('203.0.113.74')[3307]['result'] ?? null, 'denied, no finding');
        Assert::same(3, $creds('203.0.113.74')[3307]['tried'] ?? null);
        Assert::true(!isset($creds('203.0.113.74')[5985]) && !isset($creds('203.0.113.74')[8080]), 'WinRM and the Windows sign-in page: nothing tried');
        Assert::true(!isset($creds('203.0.113.72')[22]), 'SSH is never tried');
        $raw = (string) json_encode($results, JSON_UNESCAPED_UNICODE);
        Assert::notContains('"password"', $raw, 'no password field is stored');
        Assert::contains('r••t', $raw, 'masked only');
        $page = $tech->get('/engagements/' . $id)->body;
        Assert::contains('A vendor default password works on FTP (user &quot;root&quot;)', $page);
        Assert::contains('A vendor default password works on MySQL/MariaDB (user &quot;root&quot;)', $page);
        Assert::contains('(blank)', $page);
        Assert::contains('A vendor default password works on PostgreSQL (user &quot;postgres&quot;)', $page);
        Assert::contains('Redis lets anyone in without a password', $page);
        Assert::contains('Elasticsearch/OpenSearch lets anyone in without a password', $page);
        Assert::notContains('Not-A-Default', $page);
        // Running the external tests again never tries a password twice; the earlier evidence stays.
        @unlink(dirname($ctx->nmapLog) . '/creds-attempts.log');
        $runExternal($id);
        Assert::same([], $attempts($ctx), 'no login attempts on a re-run');
        Assert::contains('A vendor default password works on FTP (user &quot;root&quot;)', $tech->get('/engagements/' . $id)->body, 'earlier result kept');
        // The report says exactly what was tried.
        $tech->post('/engagements/' . $id . '/report', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
        $reports = App::reports()->forEngagement($id);
        $html = (string) (App::reports()->find((int) ($reports[0]['id'] ?? 0))['html'] ?? '');
        Assert::contains('at most three published vendor default passwords per service', $html);
        Assert::contains('A vendor default password still works', $html, 'attack path');
        // A retest re-checks only the logins that worked, one attempt each.
        $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $dcFields($site, ['name' => 'Retest', 'retest_of' => (string) $id]),
            'document', $pdf, 'application/pdf');
        $rid = $dcLast($ctx, $cid);
        $admin2->post('/engagements/' . $rid . '/approve', ['_csrf' => $admin2->get('/engagements/' . $rid)->csrf(), 'password' => 'Dcadmin2-Pass-0001!']);
        @unlink(dirname($ctx->nmapLog) . '/creds-attempts.log');
        $runExternal($rid);
        $again = array_map(static fn (array $a): string => $a[1] . ' ' . $a[2], $attempts($ctx));
        sort($again);
        Assert::same(['ftp root', 'mysql-native root', 'pg-md5 postgres'], $again, 'retest: only the accounts that worked, once each');
    },
    'default passwords internally through the agent: lockout stops, open databases, needs agent 1.29' => function (TestContext $ctx) use ($dcSetup, $dcFields, $dcLast, $attempts): void {
        [$cid, $site, $pdf] = $dcSetup($ctx);
        $tech = $ctx->login('dctech', 'Dctech-Pass-0001!');
        $admin2 = $ctx->login('dcadmin2', 'Dcadmin2-Pass-0001!');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $dir = dirname($ctx->configPath) . '/agent-defaultcreds';
        @mkdir($dir, 0700, true);
        if (!is_file($dir . '/agent.json')) {
            preg_match('/SNE(-[A-Z2-9]{5}){4}/', $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/enrol', [])->body, $m);
            [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['enrol', '--server', $ctx->baseUrl, '--code', $m[0] ?? 'missing', '--config', $dir . '/agent.json']);
            Assert::same(0, $code, 'enrol: ' . $out);
            $app = require $ctx->configPath;
            $c = json_decode((string) file_get_contents($dir . '/agent.json'), true);
            $c['nmap_path'] = $app['testing']['agent_nmap_path'];
            $c['testing'] = ['allow_documentation_ranges' => true, 'redirect_connections' => $app['testing']['redirect_connections'], 'arp_file' => $dir . '/arp', 'creds_spacing' => 0.3];
            file_put_contents($dir . '/agent.json', json_encode($c));
            file_put_contents($dir . '/arp', "IP address       HW type     Flags       HW address            Mask     Device\n");
        }
        $run = static fn (): array => $ctx->cli('bin/sentinel-agent.php', ['run', '--once', '--config', $dir . '/agent.json']);
        $run(); // reports its version
        $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $dcFields($site, ['name' => 'Internal default passwords',
            'external' => '', 'internal_' . $site => '10.89.0.0/24']), 'document', $pdf, 'application/pdf');
        $id = $dcLast($ctx, $cid);
        $admin2->post('/engagements/' . $id . '/approve', ['_csrf' => $admin2->get('/engagements/' . $id)->csrf(), 'password' => 'Dcadmin2-Pass-0001!']);
        // An agent older than 1.29.1 isn't given the job (1.28 would refuse the unknown test; 1.29.0 lacks the per-host and re-run limits).
        $ctx->db->exec("UPDATE agents SET version = '1.29.0' WHERE site_id = {$site}");
        $res = $tech->post('/engagements/' . $id . '/run-internal', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
        Assert::same([], App::agents()->engagementJobs($id), 'not queued for an old agent');
        Assert::contains('1.29.1', $tech->get('/engagements/' . $id)->body);
        $run(); // reports its real version again
        $tech->post('/engagements/' . $id . '/run-internal', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
        Assert::same(1, count(App::agents()->engagementJobs($id)), 'queued for a current agent');
        @unlink(dirname($ctx->nmapLog) . '/creds-attempts.log');
        [$code, $out] = $run();
        Assert::same(0, $code, 'agent: ' . $out);
        $modes = array_count_values(array_column($attempts($ctx), 1));
        Assert::same(1, $modes['ftp-locked'] ?? 0, 'FTP: stopped at the "too many failed logins" answer after one attempt');
        Assert::same(1, $modes['pg-scram'] ?? 0, 'PostgreSQL (SCRAM): "postgres" worked first');
        $results = App::engagements()->results($id);
        Assert::same(['10.89.0.30'], array_column($results, 'ip'));
        $page = $tech->get('/engagements/' . $id)->body;
        Assert::contains('A vendor default password works on PostgreSQL (user &quot;postgres&quot;)', $page);
        Assert::contains('MongoDB lets anyone in without a password', $page);
        Assert::contains('Memcached lets anyone in without a password', $page);
        Assert::contains('FTP signalled a lockout or block', $page);
        Assert::notContains('Redis lets anyone in', $page, 'Redis with a password is fine');
    },
];

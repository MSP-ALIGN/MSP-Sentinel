<?php

declare(strict_types=1);

/**
 * End-to-end tests for the Active Directory checks: the agent's own key, the password sealed with the real browser
 * script (agent-seal.js, run in Node's Web Crypto) and relayed by Sentinel without being readable there, the real agent
 * program collecting it, the domain controller's certificate trusted before any sign-in, the directory read against the
 * mock domain controller (tests/mocks/ldap_server.php, 10.90.0.5 through redirects), the findings and their guidance,
 * replacing the password, a changed certificate, turning the checks off, and passively heard LLMNR/NetBIOS requests.
 * Nothing real is contacted. Made-up data only.
 */

use Sentinel\AgentClient\AgentKey;
use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

const DIR_PASSWORD = 'Correct-Horse-Battery-7!';

$dirAgent = static fn (TestContext $ctx): string => dirname($ctx->configPath) . '/agent-directory';
$runDirAgent = static function (TestContext $ctx) use ($dirAgent): array {
    return $ctx->cli('bin/sentinel-agent.php', ['run', '--once', '--config', $dirAgent($ctx) . '/agent.json']);
};
$udpPort = static function (): int {
    $sock = stream_socket_server('udp://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND);
    $port = (int) substr(strrchr(stream_socket_get_name($sock, false), ':'), 1);
    fclose($sock);
    return $port;
};
$dirSetup = static function (TestContext $ctx) use ($dirAgent, $udpPort): array {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Directory Example'")->fetchColumn();
    if ($cid > 0) {
        return [$cid, (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn()];
    }
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $res = $admin->submit('/clients/new', '/clients', ['name' => 'Directory Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
    $cid = (int) basename((string) $res->location());
    $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
    $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
        'approved_by_name' => 'Sam Example', 'approved_by_role' => 'IT Manager', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
        'valid_until' => gmdate('Y-m-d', time() + 86400 * 300), 'document_ref' => 'TICKET-3001', 'notes' => '', 'ranges' => '10.90.0.0/24', 'confirm' => '1']);
    $page = $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/enrol', [])->body;
    preg_match('/SNE(-[A-Z2-9]{5}){4}/', $page, $m);
    @mkdir($dirAgent($ctx), 0700, true);
    [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['enrol', '--server', $ctx->baseUrl, '--code', $m[0] ?? 'missing', '--config', $dirAgent($ctx) . '/agent.json']);
    if ($code !== 0) {
        throw new RuntimeException('Agent enrolment failed: ' . $out);
    }
    $app = require $ctx->configPath;
    $c = json_decode((string) file_get_contents($dirAgent($ctx) . '/agent.json'), true);
    $c['nmap_path'] = $app['scanner']['nmap_path'];
    $c['testing'] = ['allow_documentation_ranges' => true, 'redirect_connections' => $app['testing']['redirect_connections'], 'arp_file' => $dirAgent($ctx) . '/arp',
        'names' => ['llmnr_port' => $udpPort(), 'nbns_port' => $udpPort(), 'loopback_as' => '10.90.0.30']];
    file_put_contents($dirAgent($ctx) . '/agent.json', json_encode($c));
    file_put_contents($dirAgent($ctx) . '/arp', "IP address       HW type     Flags       HW address            Mask     Device\n");
    return [$cid, $site];
};
/** Seal like the browser: with the real agent-seal.js in Node when available, else the same steps in PHP. */
$seal = static function (TestContext $ctx, string $publicKey, string $aad, string $password): string {
    $node = trim((string) shell_exec('command -v node 2>/dev/null'));
    if ($node !== '') {
        $p = proc_open([$node, $ctx->root . '/tests/lib/seal_with_js.mjs', $publicKey, $aad], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        fwrite($pipes[0], $password);
        fclose($pipes[0]);
        $box = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        if (proc_close($p) !== 0 || $box === '') {
            throw new RuntimeException('Sealing with agent-seal.js failed: ' . $err);
        }
        return $box;
    }
    $peer = openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n" . chunk_split($publicKey, 64, "\n") . "-----END PUBLIC KEY-----\n");
    $mine = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    $epk = base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', (string) openssl_pkey_get_details($mine)['key']));
    $key = hash_hkdf('sha256', (string) openssl_pkey_derive($peer, $mine, 32), 32, AgentKey::INFO, $epk);
    $iv = random_bytes(12);
    $ct = openssl_encrypt($password, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $aad);
    return json_encode(['v' => 1, 'epk' => base64_encode($epk), 'iv' => base64_encode($iv), 'ct' => base64_encode($ct . $tag)]);
};
/** Submit the Agents page's directory form the way the browser script does: the password only as a sealed box. */
$submitDirectory = static function (TestContext $ctx, \Sentinel\Tests\HttpClient $admin, int $cid, int $site, array $fields, ?string $password) use ($seal) {
    $page = $ctx->clientSection($admin, $cid, 'agents');
    preg_match('/data-agent-key="([^"]*)"/', $page, $key);
    preg_match('/data-aad-prefix="([^"]*)"/', $page, $aad);
    preg_match('/name="nonce" value="([0-9a-f]{32})"/', $page, $nonce);
    preg_match('/name="agent_id" value="(\d+)"/', $page, $agentId);
    $aadPrefix = html_entity_decode($aad[1] ?? '', ENT_QUOTES | ENT_HTML5);
    $sealed = $password === null ? '' : $seal($ctx, html_entity_decode($key[1] ?? '', ENT_QUOTES | ENT_HTML5), $aadPrefix . trim($fields['username']), $password);
    return $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/sites/' . $site . '/directory',
        $fields + ['sealed' => $sealed, 'nonce' => $nonce[1] ?? '', 'agent_id' => $agentId[1] ?? '', 'seal_js' => '1']);
};
$scan = static function (TestContext $ctx, int $cid, int $site) use ($runDirAgent): string {
    $ctx->login('admin', 'Admin-Pass-0001!')->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/scan', ['reason' => 'Directory test']);
    [$code, $out] = $runDirAgent($ctx);
    Assert::same(0, $code, 'agent ran: ' . $out);
    return $out;
};
$binds = static fn (TestContext $ctx): array => array_map(static fn (string $l): array => (array) json_decode($l, true),
    array_values(array_filter(explode("\n", (string) @file_get_contents(dirname($ctx->feedsLog) . '/ldap-binds.log')))));

return [
    'directory: the agent has its own key; the password is sealed in the browser and relayed, never readable in Sentinel' => function (TestContext $ctx) use ($dirSetup, $runDirAgent, $submitDirectory, $dirAgent): void {
        [$cid, $site] = $dirSetup($ctx);
        $runDirAgent($ctx); // first check-in: the agent sends its public key
        $agent = $ctx->db->query("SELECT * FROM agents WHERE site_id = {$site} AND status = 'active'")->fetch();
        Assert::true(\Sentinel\Agent\AgentRepository::validBoxKey((string) $agent['box_public_key']), 'P-256 public key recorded');
        Assert::true(is_file($dirAgent($ctx) . '/agent-key.pem') && (fileperms($dirAgent($ctx) . '/agent-key.pem') & 0077) === 0, 'private key kept on the agent, 0600');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $page = $ctx->clientSection($admin, $cid, 'agents');
        Assert::contains('Set up Active Directory checks', $page);
        Assert::contains('data-agent-key="' . $agent['box_public_key'] . '"', $page);
        Assert::notContains('name="password"', $page, 'the password field has no name: the browser never sends it');
        Assert::contains('js/agent-seal.js', $page);
        $fp = AgentKey::fingerprint((string) $agent['box_public_key']);
        Assert::contains($fp, $page, 'the agent key fingerprint is shown');
        [$code, $statusOut] = $ctx->cli('bin/sentinel-agent.php', ['status', '--config', $dirAgent($ctx) . '/agent.json']);
        Assert::contains('Agent key fingerprint: ' . $fp, $statusOut, 'and printed by the agent, to compare');

        // Validation and roles.
        $fields = ['domain' => 'corp.example', 'dc_ip' => '10.90.0.5', 'username' => 'svc-sentinel@corp.example'];
        $submitDirectory($ctx, $admin, $cid, $site, ['dc_ip' => '10.91.0.5'] + $fields, null);
        Assert::contains('must be inside the site', $ctx->clientSection($admin, $cid, 'agents'));
        $submitDirectory($ctx, $admin, $cid, $site, ['domain' => 'not a domain'] + $fields, null);
        Assert::contains('Enter the Active Directory domain name', $ctx->clientSection($admin, $cid, 'agents'));
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'dirtech'")->fetchColumn() === 0) {
            $ctx->createUser('dirtech', 'technician', 'Dirtech-Pass-0001!');
        }
        $tech = $ctx->login('dirtech', 'Dirtech-Pass-0001!');
        Assert::status(403, $tech->post('/clients/' . $cid . '/sites/' . $site . '/directory', ['_csrf' => $tech->get('/')->csrf()] + $fields), 'admins only');
        Assert::notContains('data-agent-seal', $ctx->clientSection($tech, $cid, 'agents'), 'no form for technicians');
        // A box that isn't one is refused.
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/sites/' . $site . '/directory', $fields + ['sealed' => DIR_PASSWORD, 'nonce' => str_repeat('a', 32), 'agent_id' => (string) $agent['id']]);
        Assert::contains('could not be sent sealed', $ctx->clientSection($admin, $cid, 'agents'));
        Assert::same(0, (int) $ctx->db->query('SELECT COUNT(*) FROM agent_secret_drops')->fetchColumn());

        // The page's script didn't run (blocked): nothing is saved, and the page says why (not "saved").
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/sites/' . $site . '/directory', $fields + ['sealed' => '', 'nonce' => str_repeat('a', 32), 'agent_id' => (string) $agent['id']]);
        Assert::contains('script did not run', $ctx->clientSection($admin, $cid, 'agents'));
        Assert::same(null, App::directory()->find($site));
        // The real thing: sealed with agent-seal.js, relayed, collected.
        $submitDirectory($ctx, $admin, $cid, $site, $fields, DIR_PASSWORD);
        $row = App::directory()->find($site);
        Assert::same(['corp.example', '10.90.0.5', 'svc-sentinel@corp.example', 'waiting'], [$row['domain'], $row['dc_ip'], $row['username'], $row['cred_state']]);
        $drop = $ctx->db->query('SELECT * FROM agent_secret_drops')->fetch();
        Assert::true($drop !== false && (int) $drop['agent_id'] === (int) $agent['id'], 'a drop for this agent');
        foreach (['agent_secret_drops', 'site_directory', 'audit_log', 'settings'] as $table) {
            Assert::notContains(DIR_PASSWORD, json_encode($ctx->db->query("SELECT * FROM {$table}")->fetchAll()), "never readable in {$table}");
        }
        Assert::contains('waiting for the agent to collect it', $ctx->clientSection($admin, $cid, 'agents'));
        [$code, $out] = $runDirAgent($ctx);
        Assert::contains('Directory password received and kept (sealed)', $out);
        Assert::notContains(DIR_PASSWORD, $out, 'never logged');
        Assert::same(0, (int) $ctx->db->query('SELECT COUNT(*) FROM agent_secret_drops')->fetchColumn(), 'deleted once collected');
        $row = App::directory()->find($site);
        Assert::same(['held', (int) $agent['id']], [$row['cred_state'], (int) $row['cred_agent_id']]);
        $held = (string) file_get_contents($dirAgent($ctx) . '/directory-credential.json');
        Assert::notContains(DIR_PASSWORD, $held, 'kept sealed on the agent too');
        Assert::contains('held by the agent (sealed)', $ctx->clientSection($admin, $cid, 'agents'));
        // A lost confirmation: the same drop arrives again and is confirmed again (not "replay"), nothing changes.
        $agentObj = $ctx->db->query("SELECT * FROM agents WHERE id = {$agent['id']}")->fetch();
        $nonce = bin2hex(random_bytes(16));
        $held = json_decode((string) file_get_contents($dirAgent($ctx) . '/directory-credential.json'), true);
        $ctx->db->prepare("INSERT INTO agent_secret_drops (id, agent_id, site_id, nonce, username, sealed, created_at, expires_at) VALUES (:id, :a, :s, :n, :u, :b, UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL 1 HOUR)")
            ->execute(['id' => $held['drop_id'], 'a' => $agentObj['id'], 's' => $site, 'n' => $held['nonce'], 'u' => $held['username'], 'b' => $held['sealed']]);
        $ctx->db->exec("UPDATE site_directory SET cred_state = 'waiting' WHERE site_id = {$site}");
        [$code, $out] = $runDirAgent($ctx);
        Assert::contains('received and kept', $out);
        Assert::same('held', App::directory()->find($site)['cred_state'], 'a re-sent drop is confirmed again');
        // An old box re-sent under a new drop ID (e.g. restored from a backup) is refused by its one-off number.
        $ctx->db->prepare("INSERT INTO agent_secret_drops (agent_id, site_id, nonce, username, sealed, created_at, expires_at) VALUES (:a, :s, :n, :u, :b, UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL 1 HOUR)")
            ->execute(['a' => $agentObj['id'], 's' => $site, 'n' => $held['nonce'], 'u' => $held['username'], 'b' => $held['sealed']]);
        [$code, $out] = $runDirAgent($ctx);
        Assert::contains('already used once', $out);
        $ctx->db->exec("UPDATE site_directory SET cred_state = 'held', cred_error = '' WHERE site_id = {$site}");
        Assert::same(DIR_PASSWORD, (new \Sentinel\AgentClient\Credentials($dirAgent($ctx) . '/directory-credential.json', new AgentKey($dirAgent($ctx) . '/agent-key.pem'),
            '', (int) $agentObj['id'], $site, $cid))->password(), 'the held password still opens');
    },
    'directory: no sign-in before the certificate is trusted; then the directory read becomes findings with guidance' => function (TestContext $ctx) use ($dirSetup, $scan, $binds): void {
        [$cid, $site] = $dirSetup($ctx);
        @unlink(dirname($ctx->feedsLog) . '/ldap-signing.txt');
        $before = count($binds($ctx));
        $scan($ctx, $cid, $site);
        $new = array_slice($binds($ctx), $before);
        Assert::true($new !== [], 'the signing probe ran');
        foreach ($new as $b) {
            Assert::same('plain', $b['mode'], 'no LDAPS sign-in before the certificate is trusted');
            Assert::notContains('svc-sentinel', (string) $b['name'], 'the probe uses a made-up account');
            Assert::true($b['pw_sha256'] !== hash('sha256', DIR_PASSWORD), 'never the real password on the plain port');
        }
        $row = App::directory()->find($site);
        Assert::true(preg_match('/^[0-9a-f]{64}$/', (string) $row['cert_seen']) === 1, 'certificate reported');
        Assert::same('', $row['cert_trusted']);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $page = $ctx->clientSection($admin, $cid, 'agents');
        Assert::contains('waiting for you to trust it', $page);
        Assert::contains('Trust this certificate', $page);
        // A stale fingerprint is refused; the one shown is trusted.
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/sites/' . $site . '/directory/trust', ['fingerprint' => str_repeat('0', 64)]);
        Assert::same('', App::directory()->find($site)['cert_trusted']);
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/sites/' . $site . '/directory/trust', ['fingerprint' => $row['cert_seen']]);
        Assert::same($row['cert_seen'], App::directory()->find($site)['cert_trusted']);

        $before = count($binds($ctx));
        $scan($ctx, $cid, $site);
        $ldaps = array_values(array_filter(array_slice($binds($ctx), $before), static fn (array $b): bool => $b['mode'] === 'ldaps'));
        Assert::same(1, count($ldaps), 'one sign-in');
        Assert::same(['svc-sentinel@corp.example', hash('sha256', DIR_PASSWORD)], [$ldaps[0]['name'], $ldaps[0]['pw_sha256']], 'the sealed password arrived intact');
        $row = App::directory()->find($site);
        Assert::same('', $row['last_error']);
        $f = static fn (string $code): array|false => $ctx->db->query("SELECT * FROM findings WHERE client_id = {$cid} AND finding_key = 'ad:{$site}:{$code}' AND status = 'open'")->fetch();
        foreach (['asrep' => 'fail', 'kerberoast_admin' => 'fail', 'unconstrained' => 'fail', 'kerberoast' => 'warn', 'admin_never_expires' => 'warn', 'stale_admins' => 'warn',
                  'domain_admins' => 'warn', 'krbtgt_old' => 'warn', 'laps_missing' => 'warn', 'ldap_signing' => 'warn'] as $code => $sev) {
            $row = $f($code);
            Assert::true($row !== false, "finding {$code}");
            Assert::same([$sev, 'directory', 'corp.example'], [$row['severity'], $row['finding_type'], $row['target']], $code);
        }
        Assert::contains('jexample', $f('asrep')['detail']);
        Assert::notContains('gexample', $f('asrep')['detail'], 'disabled accounts are ignored');
        Assert::contains('svc-sql', $f('kerberoast_admin')['detail']);
        Assert::contains('APP01', $f('unconstrained')['detail']);
        Assert::notContains('DC01', $f('unconstrained')['detail'], 'domain controllers are delegated by design');
        Assert::contains('WS02', $f('laps_missing')['detail']);
        Assert::notContains('WS-OLD', $f('laps_missing')['detail'], 'computers not in use are left out');
        Assert::contains('1200 days', $f('krbtgt_old')['title']);
        Assert::contains('Too many Domain Admins (7)', $f('domain_admins')['title']);
        Assert::contains('Kerberos preauthentication', \Sentinel\Reports\Guidance::for($f('asrep'))['fix'], 'how to fix it (reports and ITFlow tickets)');
        Assert::contains('jexample', $admin->get('/findings/' . (int) $f('asrep')['id'])->body, 'shown on the finding page');
        Assert::contains('Active Directory', $admin->get('/findings?type=directory')->body);
        // LDAP signing required now: that finding resolves on the next scan; the others stay.
        file_put_contents(dirname($ctx->feedsLog) . '/ldap-signing.txt', 'required');
        $scan($ctx, $cid, $site);
        Assert::same(false, $f('ldap_signing'), 'resolved');
        Assert::true($f('asrep') !== false, 'still open');
    },
    'directory: replacing the password, a wrong one, a changed certificate, a tampered box, and turning it off' => function (TestContext $ctx) use ($dirSetup, $scan, $submitDirectory, $runDirAgent, $binds, $dirAgent): void {
        [$cid, $site] = $dirSetup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $fields = ['domain' => 'corp.example', 'dc_ip' => '10.90.0.5', 'username' => 'svc-sentinel@corp.example'];
        Assert::contains('New password (leave empty to keep the current one)', $ctx->clientSection($admin, $cid, 'agents'));
        // Saving the settings alone keeps the password where it is.
        $submitDirectory($ctx, $admin, $cid, $site, $fields, null);
        Assert::same('held', App::directory()->find($site)['cred_state']);
        // Replace with a wrong password: collected, then refused by the domain controller; the earlier results stay.
        $submitDirectory($ctx, $admin, $cid, $site, $fields, 'Wrong-Password-1!');
        [$code, $out] = $runDirAgent($ctx);
        Assert::contains('Directory password received', $out);
        $scan($ctx, $cid, $site);
        $row = App::directory()->find($site);
        Assert::contains('refused the account', $row['last_error']);
        Assert::contains('refused the account', $ctx->clientSection($admin, $cid, 'agents'));
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND finding_key = 'ad:{$site}:asrep' AND status = 'open'")->fetchColumn(), 'no answer is not a fix');
        // Back to the right one.
        $submitDirectory($ctx, $admin, $cid, $site, $fields, DIR_PASSWORD);
        $runDirAgent($ctx);
        $scan($ctx, $cid, $site);
        Assert::same('', App::directory()->find($site)['last_error']);
        // The agent remembers where it signed in: a job naming another domain controller address (a compromised
        // Sentinel could sign one) gets no password until someone at the agent deletes dc-pins.json.
        Assert::contains('10.90.0.5', (string) @file_get_contents($dirAgent($ctx) . '/dc-pins.json'), 'pinned after the first sign-in');
        // (Simulated as the agent having first signed in at another address; the test network only maps .5.)
        $pins = $dirAgent($ctx) . '/dc-pins.json';
        $pinned = (string) file_get_contents($pins);
        Assert::same(['domain' => 'corp.example', 'dc_ip' => '10.90.0.5'], json_decode($pinned, true), 'one domain and address per agent');
        foreach ([['corp.example', '10.90.0.9'], ['other.example', '10.90.0.5']] as [$pd, $pip]) {
            // Another address for the domain, or another domain (a compromised Sentinel could sign either).
            file_put_contents($pins, json_encode(['domain' => $pd, 'dc_ip' => $pip]));
            $before = count($binds($ctx));
            $scan($ctx, $cid, $site);
            Assert::same([], array_values(array_filter(array_slice($binds($ctx), $before), static fn (array $b): bool => $b['mode'] === 'ldaps')), 'no sign-in: ' . $pd . ' ' . $pip);
            Assert::contains('signed in to ' . $pd . ' at ' . $pip . ' before, not corp.example at 10.90.0.5', App::directory()->find($site)['last_error']);
        }
        file_put_contents($pins, $pinned);
        // A changed certificate: the agent doesn't sign in, and says why.
        $ctx->db->exec("UPDATE site_directory SET cert_trusted = '" . str_repeat('ab', 32) . "' WHERE site_id = {$site}");
        $before = count($binds($ctx));
        $scan($ctx, $cid, $site);
        Assert::same([], array_values(array_filter(array_slice($binds($ctx), $before), static fn (array $b): bool => $b['mode'] === 'ldaps')), 'no sign-in to a certificate that changed');
        Assert::contains('certificate changed', App::directory()->find($site)['last_error']);
        Assert::contains('CHANGED since you trusted it', $ctx->clientSection($admin, $cid, 'agents'));
        $ctx->db->exec("UPDATE site_directory SET cert_trusted = cert_seen WHERE site_id = {$site}");
        // A box tampered with on the way (or sealed for another agent) is refused by the agent; the held one stays.
        $submitDirectory($ctx, $admin, $cid, $site, $fields, 'Another-Password-2!');
        $ctx->db->exec("UPDATE agent_secret_drops SET username = 'someone-else@corp.example'"); // breaks the binding
        [$code, $out] = $runDirAgent($ctx);
        Assert::contains('Directory password refused', $out);
        Assert::same('failed', App::directory()->find($site)['cred_state']);
        Assert::contains('does not open with this agent', $ctx->clientSection($admin, $cid, 'agents'));
        // A changed account whose new password never arrives: the agent deletes the old account's password.
        $submitDirectory($ctx, $admin, $cid, $site, ['username' => 'CORP\\svc-other'] + $fields, null);
        Assert::same('none', App::directory()->find($site)['cred_state']);
        [$code, $out] = $runDirAgent($ctx);
        Assert::contains('Directory password deleted', $out, 'the password for the previous account is not kept');
        $submitDirectory($ctx, $admin, $cid, $site, $fields, DIR_PASSWORD);
        $runDirAgent($ctx);
        Assert::same('held', App::directory()->find($site)['cred_state']);
        // Turning it off: settings deleted, its findings close at once, and the agent deletes its password.
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/sites/' . $site . '/directory/remove', []);
        Assert::same(null, App::directory()->find($site));
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND finding_key LIKE 'ad:{$site}:%' AND status = 'open'")->fetchColumn(), 'closed straight away');
        [$code, $out] = $runDirAgent($ctx);
        Assert::contains('Directory password deleted', $out);
        Assert::notContains('sealed', (string) file_get_contents($dirAgent($ctx) . '/directory-credential.json'));
        $ctx->login('admin', 'Admin-Pass-0001!')->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/scan', ['reason' => 'After turning off']);
        $runDirAgent($ctx);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND finding_key LIKE 'ad:{$site}:%' AND status = 'open'")->fetchColumn(), 'directory findings closed when turned off');
        $audit = implode("\n", $ctx->db->query("SELECT action FROM audit_log WHERE action LIKE '%directory%'")->fetchAll(PDO::FETCH_COLUMN));
        foreach (['site.directory_updated', 'site.directory_certificate_trusted', 'site.directory_removed', 'agent.directory_password_received', 'agent.directory_password_refused'] as $a) {
            Assert::contains($a, $audit);
        }
    },
    'directory: a changed agent key is pinned until an admin approves it; nothing is sealed to it before' => function (TestContext $ctx) use ($dirSetup, $dirAgent, $runDirAgent): void {
        [$cid, $site] = $dirSetup($ctx);
        $agent = $ctx->db->query("SELECT * FROM agents WHERE site_id = {$site} AND status = 'active'")->fetch();
        $config = json_decode((string) file_get_contents($dirAgent($ctx) . '/agent.json'), true);
        // Someone with the agent's token reports a key of their own.
        $other = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $otherKey = (string) preg_replace('/-----[^-]+-----|\s+/', '', (string) openssl_pkey_get_details($other)['key']);
        $poll = static fn (string $key): int => (int) substr((string) (@get_headers($ctx->baseUrl . '/agent/v1/poll', false, stream_context_create(['http' => [
            'method' => 'POST', 'header' => "Authorization: Bearer {$config['token']}\r\nContent-Type: application/json\r\n", 'content' => json_encode(['box_public_key' => $key]), 'ignore_errors' => true]]))[0] ?? ''), 9, 3);
        Assert::same(200, $poll($otherKey));
        $row = $ctx->db->query("SELECT box_public_key, box_key_pending FROM agents WHERE id = {$agent['id']}")->fetch();
        Assert::same([$agent['box_public_key'], $otherKey], [$row['box_public_key'], $row['box_key_pending']], 'the pinned key stays; the new one waits');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $page = $ctx->clientSection($admin, $cid, 'agents');
        Assert::contains('reported a NEW key ' . AgentKey::fingerprint($otherKey), $page);
        Assert::notContains('data-agent-seal', $page, 'no password form while a key change waits');
        Assert::contains('agent.key_change_pending', implode("\n", $ctx->db->query('SELECT action FROM audit_log')->fetchAll(PDO::FETCH_COLUMN)));
        // A wrong fingerprint isn't approved.
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/agents/' . $agent['id'] . '/approve-key', ['fingerprint' => AgentKey::fingerprint((string) $agent['box_public_key'])]);
        Assert::same($agent['box_public_key'], $ctx->db->query("SELECT box_public_key FROM agents WHERE id = {$agent['id']}")->fetchColumn());
        // The real agent's own pinned key keeps working; approving the agent's real key again (the reinstall case).
        $ctx->db->exec("UPDATE agents SET box_key_pending = '' WHERE id = {$agent['id']}");
        $ctx->db->exec("UPDATE agents SET box_public_key = " . $ctx->db->quote($otherKey) . " WHERE id = {$agent['id']}"); // as if reinstalled earlier
        $runDirAgent($ctx);
        Assert::same($agent['box_public_key'], $ctx->db->query("SELECT box_key_pending FROM agents WHERE id = {$agent['id']}")->fetchColumn(), 'the agent\'s key waits for approval');
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/agents/' . $agent['id'] . '/approve-key', ['fingerprint' => AgentKey::fingerprint((string) $agent['box_public_key'])]);
        Assert::same([$agent['box_public_key'], ''], array_values($ctx->db->query("SELECT box_public_key, box_key_pending FROM agents WHERE id = {$agent['id']}")->fetch(PDO::FETCH_NUM)));
        Assert::contains('data-agent-seal', $ctx->clientSection($admin, $cid, 'agents'), 'the form is back');
    },
    'directory: devices sending LLMNR/NetBIOS name requests are heard (never answered) and become a finding' => function (TestContext $ctx) use ($dirSetup, $runDirAgent, $dirAgent): void {
        [$cid, $site] = $dirSetup($ctx);
        $c = json_decode((string) file_get_contents($dirAgent($ctx) . '/agent.json'), true);
        $ports = $c['testing']['names'];
        // LLMNR query for "fileserv" and a NetBIOS name query for "PRINTSRV", sent repeatedly while the agent listens.
        $llmnr = pack('nnnnnn', 0x1234, 0, 1, 0, 0, 0) . "\x08fileserv\x00" . pack('nn', 1, 1);
        $nb = '';
        foreach (str_split(str_pad('PRINTSRV', 15) . "\x00") as $ch) {
            $nb .= chr(0x41 + (ord($ch) >> 4)) . chr(0x41 + (ord($ch) & 0x0F));
        }
        $nbns = pack('nnnnnn', 0x5678, 0x0110, 1, 0, 0, 0) . "\x20" . $nb . "\x00" . pack('nn', 0x20, 1);
        $answer = pack('nnnnnn', 0x1234, 0x8000, 1, 1, 0, 0) . "\x08ignoreme\x00" . pack('nn', 1, 1); // a response: not counted
        // A node-status (NBSTAT) query for "*", as inventory tools send to every address: not counted either.
        $star = '';
        foreach (str_split('*' . str_repeat("\x00", 15)) as $ch) {
            $star .= chr(0x41 + (ord($ch) >> 4)) . chr(0x41 + (ord($ch) & 0x0F));
        }
        $nbstat = pack('nnnnnn', 0x9abc, 0x0000, 1, 0, 0, 0) . "\x20" . $star . "\x00" . pack('nn', 0x21, 1);
        $script = '$end = microtime(true) + 25; $s = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP); while (microtime(true) < $end) { '
            . 'socket_sendto($s, base64_decode("' . base64_encode($llmnr) . '"), ' . strlen($llmnr) . ', 0, "127.0.0.1", ' . (int) $ports['llmnr_port'] . '); '
            . 'socket_sendto($s, base64_decode("' . base64_encode($nbns) . '"), ' . strlen($nbns) . ', 0, "127.0.0.1", ' . (int) $ports['nbns_port'] . '); '
            . 'socket_sendto($s, base64_decode("' . base64_encode($answer) . '"), ' . strlen($answer) . ', 0, "127.0.0.1", ' . (int) $ports['llmnr_port'] . '); '
            . 'socket_sendto($s, base64_decode("' . base64_encode($nbstat) . '"), ' . strlen($nbstat) . ', 0, "127.0.0.1", ' . (int) $ports['nbns_port'] . '); usleep(200000); }';
        $sender = proc_open([PHP_BINARY, '-r', $script], [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        try {
            $ctx->login('admin', 'Admin-Pass-0001!')->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/scan', ['reason' => 'Listen test']);
            $runDirAgent($ctx);
        } finally {
            proc_terminate($sender);
            proc_close($sender);
        }
        $heard = json_decode((string) $ctx->db->query("SELECT llmnr_results FROM sites WHERE id = {$site}")->fetchColumn(), true);
        Assert::same(['10.90.0.30'], array_column($heard['sources'], 'ip'), 'only the in-scope source');
        Assert::same(['llmnr', 'nbns'], $heard['sources'][0]['protocols']);
        Assert::same(['fileserv', 'PRINTSRV'], $heard['sources'][0]['names'], 'not the node-status query, not the response');
        $f = $ctx->db->query("SELECT * FROM findings WHERE client_id = {$cid} AND finding_key = 'names:{$site}:name_poisoning' AND status = 'open'")->fetch();
        Assert::true($f !== false, 'name poisoning finding');
        Assert::same('fail', $f['severity']);
        Assert::contains('10.90.0.30', $f['detail']);
        Assert::contains('LLMNR / NetBIOS', $f['detail']);
        Assert::contains('Turn off multicast name resolution', \Sentinel\Reports\Guidance::for($f)['fix'], 'how to fix it');
    },
    'directory: a quiet listen keeps devices heard earlier (no flapping); a revoked agent deletes its password' => function (TestContext $ctx) use ($dirSetup, $runDirAgent, $dirAgent, $submitDirectory): void {
        [$cid, $site] = $dirSetup($ctx);
        $ctx->login('admin', 'Admin-Pass-0001!')->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/scan', ['reason' => 'Quiet listen']);
        $runDirAgent($ctx);
        $heard = json_decode((string) $ctx->db->query("SELECT llmnr_results FROM sites WHERE id = {$site}")->fetchColumn(), true);
        Assert::same(['10.90.0.30'], array_column($heard['sources'], 'ip'), 'one quiet listen: still counted');
        Assert::same(1, $heard['quiet_runs']);
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND finding_key = 'names:{$site}:name_poisoning' AND status = 'open'")->fetchColumn());
        // Revoked: the agent wipes its sealed password before it stops.
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $submitDirectory($ctx, $admin, $cid, $site, ['domain' => 'corp.example', 'dc_ip' => '10.90.0.5', 'username' => 'svc-sentinel@corp.example'], DIR_PASSWORD);
        $runDirAgent($ctx);
        Assert::contains('sealed', (string) file_get_contents($dirAgent($ctx) . '/directory-credential.json'));
        $agentId = (int) $ctx->db->query("SELECT id FROM agents WHERE site_id = {$site} AND status = 'active'")->fetchColumn();
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/agents/' . $agentId . '/revoke', []);
        [$code, $out] = $runDirAgent($ctx);
        Assert::same(3, $code, 'stops (revoked)');
        Assert::contains('Deleting the directory password', $out);
        Assert::notContains('sealed', (string) file_get_contents($dirAgent($ctx) . '/directory-credential.json'));
    },
];

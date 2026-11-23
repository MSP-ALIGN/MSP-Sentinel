<?php

declare(strict_types=1);

/**
 * End-to-end tests for the agent release key managed on the System page: made, unlocked and used by the REAL browser
 * script (release-key.js, run in Node's Web Crypto), only its public half stored; this installation's release signed
 * in the "browser"; agents learning the key at enrolment and from a signed offer pinned by the real root helper (test
 * mode); rotation signed by the old key; a replaced key not reaching agents that pinned the old one. Made-up data only.
 * The key settings are cleared at the end, so the other tests keep using the release signed for the test run.
 */

use Sentinel\Core\App;
use Sentinel\System\ReleaseManifest;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$rkDir = static fn (TestContext $ctx): string => dirname($ctx->configPath) . '/agent-releasekey';
$rkRun = static fn (TestContext $ctx): array => $ctx->cli('bin/sentinel-agent.php', ['run', '--once', '--config', $rkDir($ctx) . '/agent.json']);
/** The real release-key.js in Node. */
$js = static function (TestContext $ctx, array $req): array {
    $p = proc_open(['node', $ctx->root . '/tests/lib/release_key_with_js.mjs'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    fwrite($pipes[0], json_encode($req));
    fclose($pipes[0]);
    $out = (string) stream_get_contents($pipes[1]);
    $err = (string) stream_get_contents($pipes[2]);
    if (proc_close($p) !== 0) {
        throw new RuntimeException('release-key.js failed: ' . $err);
    }
    return (array) json_decode($out, true);
};
$rkAgent = static function (TestContext $ctx) use ($rkDir): array {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Release Key Example'")->fetchColumn();
    if ($cid === 0) {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Release Key Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
        $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
            'approved_by_name' => 'Sam Example', 'approved_by_role' => 'IT Manager', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
            'valid_until' => gmdate('Y-m-d', time() + 86400 * 300), 'document_ref' => 'TICKET-7001', 'notes' => '', 'ranges' => '10.95.0.0/24', 'confirm' => '1']);
        $page = $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/enrol', [])->body;
        preg_match('/SNE(-[A-Z2-9]{5}){4}/', $page, $m);
        @mkdir($rkDir($ctx), 0700, true);
        [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['enrol', '--server', $ctx->baseUrl, '--code', $m[0] ?? 'missing', '--config', $rkDir($ctx) . '/agent.json']);
        if ($code !== 0) {
            throw new RuntimeException('Agent enrolment failed: ' . $out);
        }
        $app = require $ctx->configPath;
        $c = json_decode((string) file_get_contents($rkDir($ctx) . '/agent.json'), true);
        $c['nmap_path'] = $app['scanner']['nmap_path'];
        $c['testing'] = ['allow_documentation_ranges' => true, 'redirect_connections' => $app['testing']['redirect_connections'],
            'release_key' => $rkDir($ctx) . '/release-key.pub', 'update_result_dir' => $rkDir($ctx) . '-results'];
        file_put_contents($rkDir($ctx) . '/agent.json', json_encode($c));
    }
    $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
    return [$cid, $site, (int) $ctx->db->query("SELECT id FROM agents WHERE site_id = {$site} AND status = 'active'")->fetchColumn()];
};
$helper = static fn (TestContext $ctx): array => $ctx->cli('bin/agent-update-runner.php', ['--app', dirname($ctx->configPath) . '/rk-app', '--state', $rkDir($ctx),
    '--key', $rkDir($ctx) . '/release-key.pub', '--result', $rkDir($ctx) . '-results', '--config', $rkDir($ctx) . '/agent.json', '--no-systemd']);

return [
    'release key: made in the browser (only the public half stored), this version signed in the browser, agents pin it' => function (TestContext $ctx) use ($js, $rkAgent, $rkRun, $rkDir, $helper): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        // The made-up release ships a key file (as one signed with bin/release-sign.php would): set it aside, so this
        // installation starts with no release key at all.
        $fileKey = (string) (require $ctx->configPath)['testing']['release_root'] . '/install/release-key.pub';
        rename($fileKey, $fileKey . '.aside');
        try {
            Assert::contains('Create release key (downloads the key file)', $admin->get('/admin/system')->body);
            $k = $js($ctx, ['op' => 'create', 'password' => 'Key-File-Password-1']);
            Assert::contains('"type": "msp-sentinel-release-key"', $k['file']);
            Assert::notContains('PRIVATE', $k['file'], 'the private key is only stored encrypted');
            // The Sentinel password is required; only the public key is sent.
            $admin->submit('/admin/system', '/admin/system/release-key', ['mode' => 'create', 'public_key' => $k['publicKey'], 'password' => 'wrong']);
            Assert::same('', App::releaseKey()['key']);
            $admin->submit('/admin/system', '/admin/system/release-key', ['mode' => 'create', 'public_key' => $k['publicKey'], 'password' => 'Admin-Pass-0001!']);
            Assert::same($k['publicKey'], App::releaseKey()['key']);
            Assert::notContains($k['publicKey'], (string) App::settings()->fresh('release_key'), 'stored authenticated with the app key, not as plain text');
            Assert::same(ReleaseManifest::keyFingerprint($k['publicKey']), $k['fingerprint'], 'the browser shows the same fingerprint as Sentinel');
            Assert::same('sentinel-release-key-' . str_replace(':', '-', substr($k['fingerprint'], 0, 9)) . '.json', $k['fileName']);
            Assert::notContains((string) json_decode($k['file'], true)['ct'], json_encode($ctx->db->query('SELECT * FROM settings')->fetchAll()), 'nothing of the private key in Sentinel');
            $page = $admin->get('/admin/system')->body;
            Assert::contains(ReleaseManifest::keyFingerprint($k['publicKey']), $page);
            Assert::contains('Sign version 9.9.9', $page);
            // Sign this installation's release in the "browser" with the key file; a wrong signature is refused.
            preg_match('/name="manifest" value="([^"]*)"/', $page, $mm);
            $manifest = html_entity_decode($mm[1] ?? '', ENT_QUOTES | ENT_HTML5);
            Assert::true(is_array(json_decode($manifest, true)), 'the page carries the manifest to sign');
            Assert::contains('Manifest SHA-256: ' . hash('sha256', $manifest), $page, 'the admin can compare it with the published one');
            // Only the release's own files are signed: nothing else left in the server's folder.
            $releaseRoot = dirname($fileKey, 2);
            file_put_contents($releaseRoot . '/database-dump.sql', 'made-up');
            file_put_contents($releaseRoot . '/src/notes.bak', 'made-up');
            $listed = array_keys(json_decode((string) App::agentRelease()->manifestToSign(), true)['files']);
            unlink($releaseRoot . '/database-dump.sql');
            unlink($releaseRoot . '/src/notes.bak');
            Assert::true(!in_array('database-dump.sql', $listed, true) && !in_array('src/notes.bak', $listed, true), 'stray files are never signed');
            Assert::true(in_array('bin/sentinel-agent.php', $listed, true), 'release files are');
            $admin->submit('/admin/system', '/admin/system/release-sign', ['manifest' => $manifest, 'signature' => base64_encode(str_repeat('x', 64))]);
            Assert::same(null, App::agentRelease()->version(), 'a bad signature is not kept');
            $sig = $js($ctx, ['op' => 'sign', 'file' => $k['file'], 'password' => 'Key-File-Password-1', 'text' => $manifest]);
            $admin->submit('/admin/system', '/admin/system/release-sign', ['manifest' => $manifest, 'signature' => $sig['signature']]);
            Assert::same('9.9.9', App::agentRelease()->version(), 'signed in the browser');
            Assert::contains('This version is signed', $admin->get('/admin/system')->body);
            $threw = false;
            try {
                $js($ctx, ['op' => 'sign', 'file' => $k['file'], 'password' => 'Wrong-Password-9', 'text' => 'x']);
            } catch (RuntimeException) {
                $threw = true;
            }
            Assert::true($threw, 'a wrong key file password opens nothing');

            // A new agent gets the key at enrolment.
            [$cid, $site, $agentId] = $rkAgent($ctx);
            Assert::same($k['publicKey'], json_decode((string) file_get_contents($rkDir($ctx) . '/agent.json'), true)['release_public_key'] ?? null, 'pinned at enrolment');
            $rkRun($ctx);
            Assert::same(ReleaseManifest::keyFingerprint($k['publicKey']), $ctx->db->query("SELECT release_key_fp FROM agents WHERE id = {$agentId}")->fetchColumn());
            // The key pinned at enrolment (only in the root-owned config, no key file) is enough for the helper to update.
            Assert::true(!is_file($rkDir($ctx) . '/release-key.pub'), 'no key file yet');
            @mkdir(dirname($ctx->configPath) . '/rk-app/bin', 0700, true);
            file_put_contents(dirname($ctx->configPath) . '/rk-app/VERSION', "1.24.0\n");
            file_put_contents(dirname($ctx->configPath) . '/rk-app/bin/sentinel-agent.php', "<?php // installed 1.24.0\n");
            $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/agents/' . $agentId . '/update', []);
            [$code, $out] = $rkRun($ctx);
            Assert::contains('Update to 9.9.9 staged', $out);
            [$code, $out] = $helper($ctx);
            Assert::same(0, $code, 'helper: ' . $out);
            Assert::same("9.9.9\n", file_get_contents(dirname($ctx->configPath) . '/rk-app/VERSION'), 'updated with the key pinned at enrolment');
            $rkRun($ctx); // reports the result and cleans up
            Assert::same(['9.9.9', true], [json_decode((string) $ctx->db->query("SELECT update_result FROM agents WHERE id = {$agentId}")->fetchColumn(), true)['version'] ?? null,
                json_decode((string) $ctx->db->query("SELECT update_result FROM agents WHERE id = {$agentId}")->fetchColumn(), true)['ok'] ?? null]);
            // An agent without a key (enrolled before) is offered it and the root helper pins it.
            $c = json_decode((string) file_get_contents($rkDir($ctx) . '/agent.json'), true);
            $c['release_public_key'] = '';
            file_put_contents($rkDir($ctx) . '/agent.json', json_encode($c));
            [$code, $out] = $rkRun($ctx);
            Assert::contains('Release key offered by Sentinel', $out);
            [$code, $out] = $helper($ctx);
            Assert::same(0, $code, 'helper: ' . $out);
            Assert::same($k['publicKey'] . "\n", file_get_contents($rkDir($ctx) . '/release-key.pub'), 'pinned by the helper');
            $rkRun($ctx);
            Assert::same(ReleaseManifest::keyFingerprint($k['publicKey']), $ctx->db->query("SELECT release_key_fp FROM agents WHERE id = {$agentId}")->fetchColumn());

            // Rotation: the old key signs the change; the agent accepts the new key on its own. Rotated twice while the
            // agent was away: it follows the chain (each step signed by the key before) to the current key.
            $r1 = $js($ctx, ['op' => 'rotate', 'file' => $k['file'], 'password' => 'Key-File-Password-1', 'newPassword' => 'Key-File-Password-2', 'at' => gmdate('Y-m-d\TH:i:s\Z')]);
            $admin->submit('/admin/system', '/admin/system/release-key', ['mode' => 'rotate', 'public_key' => $r1['publicKey'], 'statement' => $r1['statement'],
                'statement_signature' => base64_encode(str_repeat('y', 64)), 'password' => 'Admin-Pass-0001!']);
            Assert::same($k['publicKey'], App::releaseKey()['key'], 'an unsigned change is refused');
            $admin->submit('/admin/system', '/admin/system/release-key', ['mode' => 'rotate', 'public_key' => $r1['publicKey'], 'statement' => $r1['statement'],
                'statement_signature' => $r1['signature'], 'password' => 'Admin-Pass-0001!']);
            Assert::same($r1['publicKey'], App::releaseKey()['key']);
            $r = $js($ctx, ['op' => 'rotate', 'file' => $r1['file'], 'password' => 'Key-File-Password-2', 'newPassword' => 'Key-File-Password-4', 'at' => gmdate('Y-m-d\TH:i:s\Z')]);
            $admin->submit('/admin/system', '/admin/system/release-key', ['mode' => 'rotate', 'public_key' => $r['publicKey'], 'statement' => $r['statement'],
                'statement_signature' => $r['signature'], 'password' => 'Admin-Pass-0001!']);
            Assert::same($r['publicKey'], App::releaseKey()['key']);
            Assert::same(2, count(App::releaseKey()['chain']));
            Assert::contains('follows the rotation at its next check-in', $admin->get('/admin/system')->body);
            Assert::same(null, App::agentRelease()->version(), 'sign again with the new key');
            $ctx->db->exec("UPDATE agents SET key_offered_at = NULL WHERE id = {$agentId}");
            [$code, $out] = $rkRun($ctx);
            Assert::contains('Release key offered', $out);
            [$code, $out] = $helper($ctx);
            Assert::same(0, $code, 'helper: ' . $out);
            Assert::contains('Release key rotated', $out);
            Assert::same($r['publicKey'] . "\n", file_get_contents($rkDir($ctx) . '/release-key.pub'), 'two rotations followed');

            // A replaced key (the old file lost) never reaches agents that pinned another key; the page says so.
            $lost = $js($ctx, ['op' => 'create', 'password' => 'Key-File-Password-3']);
            $admin->submit('/admin/system', '/admin/system/release-key', ['mode' => 'replace', 'public_key' => $lost['publicKey'], 'password' => 'Admin-Pass-0001!']);
            $ctx->db->exec("UPDATE agents SET key_offered_at = NULL WHERE id = {$agentId}");
            $rkRun($ctx);
            $rkRun($ctx);
            Assert::same($r['publicKey'] . "\n", file_get_contents($rkDir($ctx) . '/release-key.pub'), 'not changed without the pinned key\'s signature');
            Assert::contains('give it the new key by hand', $admin->get('/admin/system')->body);
            // A forged offer (not signed by Sentinel) is refused by the helper.
            file_put_contents($rkDir($ctx) . '/release-key-offer.json', json_encode(['payload' => json_encode(['type' => 'agent_release_key', 'agent_id' => $agentId, 'key' => $lost['publicKey'],
                'issued_at' => gmdate('Y-m-d\TH:i:s\Z')]), 'signature' => base64_encode(str_repeat('z', 64))]));
            file_put_contents($rkDir($ctx) . '/update-request', json_encode(['kind' => 'pin', 'request' => gmdate('Y-m-d\TH:i:s\Z')]));
            [$code, $out] = $helper($ctx);
            Assert::same(1, $code);
            Assert::contains('not signed by this agent', $out);
            Assert::same($r['publicKey'] . "\n", file_get_contents($rkDir($ctx) . '/release-key.pub'));
            // A database write alone can't plant a release key: the value must be authenticated with the app key.
            $attacker = $js($ctx, ['op' => 'create', 'password' => 'Key-File-Password-5']);
            App::settings()->set('release_key', (string) json_encode(['key' => $attacker['publicKey'], 'chain' => []]));
            Assert::same('', App::agentRelease()->publicKey(), 'an unauthenticated key is no key');
            $ctx->db->exec("UPDATE agents SET key_offered_at = NULL WHERE id = {$agentId}");
            $rkRun($ctx);
            Assert::true(!is_file($rkDir($ctx) . '/release-key-offer.json') || !str_contains((string) file_get_contents($rkDir($ctx) . '/release-key-offer.json'), $attacker['publicKey']), 'never offered');
            $audit = implode("\n", $ctx->db->query("SELECT action FROM audit_log WHERE action LIKE 'release_key.%'")->fetchAll(PDO::FETCH_COLUMN));
            foreach (['release_key.create', 'release_key.signed', 'release_key.rotate', 'release_key.replace'] as $a) {
                Assert::contains($a, $audit);
            }
        } finally {
            rename($fileKey . '.aside', $fileKey);
            // The other tests use the release signed for the test run (install/release-key.pub of the made-up release).
            App::settings()->set('release_key', '');
            \Sentinel\AgentClient\Updater::removeTree((string) (require $ctx->configPath)['testing']['release_ui_dir']);
        }
    },
];

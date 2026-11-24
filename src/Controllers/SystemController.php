<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;

/**
 * Admin System page: health checks, version and updates, data retention.
 *
 * Access (enforced by the routes): admins only.
 *
 * Untrusted: retention months (whole numbers 0-120), the update-check toggle.
 *
 * Security assumptions: health results contain no secrets; changes are audited;
 * retention never touches the audit log.
 */
final class SystemController extends Controller
{
    /** GET /admin/system */
    public function index(Request $request): Response
    {
        $s = App::settings();
        return $this->page('admin/system', __('System'), [
            'checks' => App::health()->run(),
            'backups' => (new \Sentinel\System\BackupStatus(App::settings()))->history(),
            'backupExternal' => App::settings()->fresh('backup_external') === '1',
            'version' => App::version(),
            'build' => App::build(),
            'demoLoaded' => (new \Sentinel\Demo\DemoData(App::db(), (int) $this->user()['id']))->isLoaded(),
            'newer' => App::updates()->newer(),
            'branchStatus' => App::updates()->branchStatus(),
            'webUpdate' => ['available' => App::webUpdate()->available(), 'pending' => App::webUpdate()->pending(), 'unclaimed' => App::webUpdate()->unclaimed(),
                            'wait' => App::webUpdate()->waitSeconds(), 'status' => App::webUpdate()->status(), 'log' => App::webUpdate()->log()],
            'updateEnabled' => $s->get('update_check_enabled') === '1',
            'checkedAt' => $s->get('update_checked_at'),
            'retention' => ['scans' => $s->get('retention_scans_months'), 'findings' => $s->get('retention_findings_months'), 'reports' => $s->get('retention_reports_months')],
            'retentionLast' => $s->get('retention_last_run'),
            'sourceUrl' => $s->get('source_url'),
            'agentRelease' => App::agentRelease(),
            'releaseKey' => ['key' => App::agentRelease()->publicKey(), 'created' => App::releaseKey()['created_at'],
                // Agents holding one of these (older keys of the rotation chain) follow it to the current key on their own.
                'followable' => array_map(static fn (array $l): string => \Sentinel\System\ReleaseManifest::keyFingerprint($l['old_key']), App::releaseKey()['chain']),
                'manifest' => App::agentRelease()->version() === null ? App::agentRelease()->manifestToSign() : null],
            'agentMove' => ['url' => App::agentMove()['url'], 'ca' => App::agentMove()['ca'] !== '', 'since' => App::agentMove()['requested_at'], 'complete' => App::agentMove()['complete'],
                'agents' => App::db()->query("SELECT a.id, a.name, a.server_url, a.version, a.move_result, a.move_result_at, a.release_key_fp, c.name AS client_name FROM agents a JOIN clients c ON c.id = a.client_id
                                              WHERE a.status = 'active' AND c.is_demo = 0 ORDER BY c.name, a.name")->fetchAll()],
            'agentVersions' => App::db()->query("SELECT a.version, COUNT(*) AS n FROM agents a JOIN clients c ON c.id = a.client_id WHERE a.status = 'active' AND c.is_demo = 0 GROUP BY a.version ORDER BY a.version")->fetchAll(),
        ]);
    }

    /**
     * POST /admin/system/agents-move (admins): move every agent to a new Sentinel address (and CA), or cancel
     * (cancel=1). Each agent switches only after the new address proves it holds this Sentinel's key, and goes back on
     * its own if the new address then keeps failing.
     */
    public function moveAgents(Request $request): Response
    {
        $s = App::settings();
        $back = Response::redirect('/admin/system#agents');
        // Moving (or recalling) every agent is powerful: the signed-in admin confirms it with their password (throttled,
        // failures audited), so a stolen session alone can't do it.
        $user = App::db()->query('SELECT id, password_hash FROM users WHERE id = ' . (int) $this->user()['id'])->fetch() ?: [];
        if (($reauth = $this->checkCurrentPassword($request, $user, $request->raw('password'))) !== null) {
            Session::flash('danger', __('Enter your password to confirm.') . ' ' . $reauth);
            return $back;
        }
        $current = App::agentMove();
        if ($request->input('cancel') === '1') {
            // Cancel = recall: moved agents ask their original address every few hours and come back.
            $s->setSecret('agent_move', '');
            $this->audit($request, 'agent.move_cancelled');
            Session::flash('success', __('Agent move cancelled: agents that moved come back to their original address within about 6 hours (keep it working).'));
            return $back;
        }
        if ($request->input('complete') === '1' && $current['url'] !== '') {
            // Complete: no more move instructions, but moved agents keep the new address (recall keeps confirming it).
            $s->setSecret('agent_move', (string) json_encode(['complete' => true] + $current, JSON_UNESCAPED_SLASHES));
            $this->audit($request, 'agent.move_completed', null, null, ['url' => $current['url']]);
            Session::flash('success', __('Move marked complete: moved agents stay on {url}; no more agents are asked to move.', ['url' => $current['url']]));
            return $back;
        }
        $url = rtrim($request->input('url'), '/');
        $ca = trim($request->raw('ca'));
        $error = match (true) {
            !\Sentinel\AgentClient\Mover::validServer($url, App::webhookTestMode()) => __('Enter the new address as https://host or https://host:port.'),
            $ca !== '' && (strlen($ca) > 32768 || preg_match_all('/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/s', $ca, $m) < 1) => __('The CA must be one or more PEM certificates.'),
            default => null,
        };
        if ($error === null && $ca !== '') {
            foreach ($m[0] as $pem) {
                if (@openssl_x509_read($pem) === false) {
                    $error = __('The CA must be one or more PEM certificates.');
                }
            }
        }
        if ($error !== null) {
            Session::flash('danger', $error);
            return $back;
        }
        // One value, encrypted and authenticated with the app key: a database write alone can't set a move.
        $s->setSecret('agent_move', (string) json_encode(['url' => $url, 'ca' => $ca, 'id' => bin2hex(random_bytes(8)),
            'requested_at' => (string) App::db()->query('SELECT UTC_TIMESTAMP()')->fetchColumn()], JSON_UNESCAPED_SLASHES));
        $this->audit($request, 'agent.move_requested', null, null, ['url' => $url, 'ca' => $ca !== '']);
        Session::flash('success', __('Agents move to {url} at their next check-in between scans, each after the new address proves it is this Sentinel.', ['url' => $url]));
        return $back;
    }

    /**
     * POST /admin/system/release-key (admins, with their password): set the agent release key made in the admin's
     * browser. Only the PUBLIC key arrives here; the private key stays in the file the browser downloaded.
     * - create: when there is no key yet;
     * - rotate: a new key, with a statement naming it signed by the current key (agents accept it on their own);
     * - replace: the old key file was lost (agents must be given the new key by hand: /etc/sentinel-agent/release-key.pub, see docs/agent.md).
     */
    public function releaseKey(Request $request): Response
    {
        $back = Response::redirect('/admin/system#agents');
        $user = App::db()->query('SELECT id, password_hash FROM users WHERE id = ' . (int) $this->user()['id'])->fetch() ?: [];
        if (($reauth = $this->checkCurrentPassword($request, $user, $request->raw('password'))) !== null) {
            Session::flash('danger', __('Enter your Sentinel password to confirm.') . ' ' . $reauth);
            return $back;
        }
        $mode = $request->input('mode');
        $new = trim($request->input('public_key'));
        $current = App::agentRelease()->publicKey();
        $error = match (true) {
            !\Sentinel\System\ReleaseManifest::validPublicKey($new) => __('The key could not be made in your browser (open Sentinel over HTTPS).'),
            $new === $current => __('That is already the release key.'),
            $mode === 'create' && $current !== '' => __('There is already a release key: rotate it instead.'),
            !in_array($mode, ['create', 'rotate', 'replace'], true) => __('Unknown request.'),
            $mode !== 'create' && $current === '' => __('Create a release key first.'),
            default => null,
        };
        $statement = $request->raw('statement');
        if ($error === null && $mode === 'rotate') {
            $st = json_decode($statement, true);
            $sig = base64_decode($request->input('statement_signature'), true);
            $error = !is_array($st) || ($st['type'] ?? null) !== 'release_key_rotation' || ($st['old_key'] ?? null) !== $current || ($st['new_key'] ?? null) !== $new
                || $sig === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES || !sodium_crypto_sign_verify_detached($sig, $statement, (string) base64_decode($current))
                ? __('The old key file did not sign the change (wrong key file or password?).') : null;
        }
        if ($error !== null) {
            Session::flash('danger', $error);
            return $back;
        }
        // A rotation extends the chain agents follow (each link signed by the key before it); a new or replaced key starts
        // a new chain (agents that pinned an older key need it by hand).
        App::setReleaseKey($new, $mode === 'rotate' ? [...App::releaseKey()['chain'], ['statement' => $statement, 'signature' => $request->input('statement_signature')]] : []);
        $this->audit($request, 'release_key.' . $mode, null, null, ['fingerprint' => \Sentinel\System\ReleaseManifest::keyFingerprint($new)]);
        Session::flash('success', match ($mode) {
            'create' => __('Release key created. Keep the downloaded key file and its password safe: you need both to sign releases. Now sign this version below.'),
            'rotate' => __('Release key rotated: agents switch to the new key on their own. Keep the new key file safe, and sign this version again with it.'),
            default => __('Release key replaced. Agents that pinned the old key must be given the new one by hand (see the list below). Sign this version with the new key.'),
        });
        return $back;
    }

    /**
     * POST /admin/system/backups (admins): whether backups are made another way (VM snapshots...), so Sentinel neither
     * warns nor alerts about its own backup job (1.37.1). Untrusted: the checkbox (only '1' turns it on). Audited.
     */
    public function backups(Request $request): Response
    {
        $external = $request->input('backup_external') === '1';
        App::settings()->set('backup_external', $external ? '1' : '0');
        $this->audit($request, 'settings.backup_external', null, null, ['external' => $external]);
        Session::flash('success', $external ? __('Saved: Sentinel no longer warns about its own backups.') : __('Saved: Sentinel checks its backups again.'));
        return Response::redirect('/admin/system#backups');
    }

    /** POST /admin/system/release-sign (admins): keep the signature the admin's browser made for this installation's files. */
    public function releaseSign(Request $request): Response
    {
        // The admin confirmed the manifest by its hash (from the release notes, or computed on their own computer); the
        // browser checked it before signing and it is checked again here, and kept in the audit log (1.35).
        $expected = strtolower(trim($request->input('expected_hash')));
        if (preg_match('/^[0-9a-f]{64}$/', $expected) !== 1 || !hash_equals($expected, hash('sha256', $request->raw('manifest')))) {
            Session::flash('danger', __('The expected manifest hash is missing or does not match what would be signed. Nothing was signed.'));
            return Response::redirect('/admin/system#agents');
        }
        $error = App::agentRelease()->acceptSignature($request->raw('manifest'), trim($request->input('signature')));
        if ($error !== '') {
            Session::flash('danger', $error);
        } else {
            $this->audit($request, 'release_key.signed', null, null, ['version' => App::agentRelease()->version(), 'manifest_sha256' => $expected]);
            Session::flash('success', __('Version {v} signed. Agents can be updated to it.', ['v' => App::agentRelease()->version() ?? '?']));
        }
        return Response::redirect('/admin/system#agents');
    }

    /** POST /admin/system/agents-update (admins): every agent of every client that can and needs to update. */
    public function updateAgents(Request $request): Response
    {
        $release = App::agentRelease()->version();
        if ($release === null) {
            Session::flash('warning', __('This Sentinel has no signed agent release to hand out: {why}.', ['why' => App::agentRelease()->why()]));
            return Response::redirect('/admin/system#agents');
        }
        $n = App::agents()->requestUpdates(null, $release, (int) $this->user()['id']);
        $this->audit($request, 'agent.update_requested', null, null, ['version' => $release, 'scope' => 'all'] + $n);
        Session::flash('success', __('{n} agent(s) will update to {v}.', ['n' => $n['asked'], 'v' => $release])
            . ($n['manual'] > 0 ? ' ' . __('{m} must be upgraded once by hand first.', ['m' => $n['manual']]) : '')
            . ($n['image'] > 0 ? ' ' . __('{d} run in Docker: pull the new image for those.', ['d' => $n['image']]) : ''));
        return Response::redirect('/admin/system#agents');
    }

    /**
     * POST /admin/system/demo (admins; CSRF-checked like every POST): load or remove the demo data.
     * Untrusted: "action" (only "load" or "remove" do anything). Demo clients are never scanned (see DemoData).
     */
    public function demo(Request $request): Response
    {
        @set_time_limit(120);
        $demo = new \Sentinel\Demo\DemoData(App::db(), (int) $this->user()['id']);
        try {
            if ($request->input('action') === 'remove') {
                $r = $demo->remove();
                $this->audit($request, 'demo.removed', null, null, $r);
                Session::flash('success', __('Removed {n} demo client(s) and everything that belonged to them.', ['n' => $r['clients']]));
            } elseif ($request->input('action') === 'load') {
                if ($demo->isLoaded()) {
                    Session::flash('info', __('Demo data is already loaded.'));
                } else {
                    $r = $demo->load();
                    $this->audit($request, 'demo.loaded', null, null, $r);
                    Session::flash('success', __('Loaded {c} demo clients with {f} findings, {d} devices and {r} reports. They are never scanned.', ['c' => $r['clients'], 'f' => $r['findings'], 'd' => $r['devices'], 'r' => $r['reports']]));
                }
            }
        } catch (\Throwable $ex) {
            error_log('MSP Sentinel demo data: ' . $ex->getMessage());
            Session::flash('danger', __('The demo data could not be changed. The error is in the web server log.'));
        }
        return Response::redirect('/admin/system#demo');
    }

    /**
     * POST /admin/system/update (admins; CSRF-checked like every POST): ask the server's update runner to run
     * msp-sentinel-update. One click (the form asks "Are you sure?"): the runner can only run that fixed update,
     * backs up first, and starts at most once every 15 minutes, so a second confirmation adds little.
     * Untrusted input: none (the request carries no data).
     */
    public function update(Request $request): Response
    {
        $back = Response::redirect('/admin/system#updates');
        $wu = App::webUpdate();
        if ($request->input('action') === 'cancel') {
            $wu->cancel();
            $this->audit($request, 'system.update_cancelled');
            Session::flash('info', __('The waiting update request was removed.'));
            return $back;
        }
        if (!$wu->request()) {
            $wait = $wu->waitSeconds();
            $reason = !$wu->available() ? 'not set up on this server' : ($wait > 0 ? 'less than 15 minutes since the last update' : 'already waiting or running');
            $this->audit($request, 'system.update_denied', null, null, ['reason' => $reason]);
            Session::flash('warning', match (true) {
                !$wu->available() => __('Updating from the web interface is not set up on this server. Run sudo msp-sentinel-update on the server.'),
                $wait > 0 => __('An update ran less than 15 minutes ago. You can start the next one in {m} minute(s).', ['m' => (int) ceil($wait / 60)]),
                default => __('An update is already waiting or running.'),
            });
            return $back;
        }
        $this->audit($request, 'system.update_requested', null, null, ['version' => App::version(), 'build' => App::build()['commit'] ?? null]);
        Session::flash('success', __('Update requested. The server starts it within a few seconds: Sentinel backs up first, and may be unavailable for a minute while it restarts. Refresh this page to follow it.'));
        return $back;
    }

    /** POST /admin/system/retention */
    public function retention(Request $request): Response
    {
        $s = App::settings();
        $changed = [];
        foreach (['scans', 'findings', 'reports'] as $k) {
            $v = $request->input('retention_' . $k);
            if (!ctype_digit($v) || (int) $v > 120 || ($v !== '0' && str_starts_with($v, '0'))) {
                Session::flash('danger', __('Enter whole months from 0 (keep forever) to 120.'));
                return Response::redirect('/admin/system#retention');
            }
            if ($s->get('retention_' . $k . '_months') !== $v) {
                $s->set('retention_' . $k . '_months', $v);
                $changed[$k] = (int) $v;
            }
        }
        if ($changed !== []) {
            $this->audit($request, 'settings.retention_updated', null, null, ['months' => $changed]);
        }
        Session::flash('success', __('Retention saved. Old data is removed by the worker once a day.'));
        return Response::redirect('/admin/system#retention');
    }

    /** POST /admin/system/updates: turn the check on/off, or check now. */
    public function updates(Request $request): Response
    {
        $s = App::settings();
        if ($request->input('action') === 'check') {
            $v = App::updates()->check(true);
            Session::flash($v === null ? 'warning' : 'success', $v === null
                ? __('The update check did not get an answer (it may be off, or the server cannot reach the releases feed).')
                : (App::updates()->newer() !== null ? __('Version {v} is available.', ['v' => $v]) : __('You are up to date ({v}).', ['v' => App::version()])));
        } else {
            $on = $request->input('update_check_enabled') === '1';
            $s->set('update_check_enabled', $on ? '1' : '0');
            $this->audit($request, 'settings.update_check', null, null, ['enabled' => $on]);
            Session::flash('success', $on ? __('Update check turned on.') : __('Update check turned off.'));
        }
        return Response::redirect('/admin/system#updates');
    }
}

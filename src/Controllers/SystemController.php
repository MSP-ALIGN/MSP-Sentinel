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
            'agentMove' => ['url' => $s->get('agent_move_url'), 'ca' => $s->get('agent_move_ca') !== '', 'since' => $s->get('agent_move_requested_at'),
                'agents' => App::db()->query("SELECT a.id, a.name, a.server_url, a.version, a.move_result, a.move_result_at, c.name AS client_name FROM agents a JOIN clients c ON c.id = a.client_id
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
        if ($request->input('cancel') === '1') {
            $s->set('agent_move_url', '');
            $s->set('agent_move_ca', '');
            $this->audit($request, 'agent.move_cancelled');
            Session::flash('success', __('Agent move cancelled. Agents that already moved stay on the new address.'));
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
        $s->set('agent_move_url', $url);
        $s->set('agent_move_ca', $ca);
        $s->set('agent_move_requested_at', gmdate('Y-m-d H:i:s'));
        $this->audit($request, 'agent.move_requested', null, null, ['url' => $url, 'ca' => $ca !== '']);
        Session::flash('success', __('Agents move to {url} at their next check-in between scans, each after the new address proves it is this Sentinel.', ['url' => $url]));
        return $back;
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
            . ($n['manual'] > 0 ? ' ' . __('{m} must be upgraded once by hand first.', ['m' => $n['manual']]) : ''));
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

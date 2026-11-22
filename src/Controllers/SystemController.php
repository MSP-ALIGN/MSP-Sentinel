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
            'webUpdate' => ['available' => App::webUpdate()->available(), 'pending' => App::webUpdate()->pending(), 'status' => App::webUpdate()->status(), 'log' => App::webUpdate()->log()],
            'updateEnabled' => $s->get('update_check_enabled') === '1',
            'checkedAt' => $s->get('update_checked_at'),
            'retention' => ['scans' => $s->get('retention_scans_months'), 'findings' => $s->get('retention_findings_months'), 'reports' => $s->get('retention_reports_months')],
            'retentionLast' => $s->get('retention_last_run'),
            'sourceUrl' => $s->get('source_url'),
        ]);
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
     * msp-sentinel-update. Re-checks the admin's password and a fresh 2FA code first, because this starts an
     * upgrade as root on the server; at most 5 tries per 15 minutes per admin.
     * Untrusted: "password" and "code" (only compared, never stored or logged).
     */
    public function update(Request $request): Response
    {
        $user = $this->user();
        $id = (int) $user['id'];
        $back = Response::redirect('/admin/system#updates');
        $bucket = 'web_update:' . $id;
        if (App::limiter()->tooMany($bucket, 5, 900)) {
            $this->audit($request, 'system.update_denied', null, null, ['reason' => 'too many attempts']);
            Session::flash('danger', __('Too many attempts. Wait 15 minutes and try again.'));
            return $back;
        }
        App::limiter()->hit($bucket);
        $fresh = App::db()->prepare('SELECT password_hash, totp_secret_enc, totp_enabled_at, totp_last_step FROM users WHERE id = :id');
        $fresh->execute(['id' => $id]);
        $row = $fresh->fetch();
        $code = preg_replace('/\s+/', '', $request->input('code')) ?? '';
        $ok = $row !== false && \Sentinel\Auth\Passwords::verify($request->input('password'), (string) $row['password_hash']);
        if ($ok) {
            // 2FA is required for every admin; a code is single-use (the step is claimed like at sign-in).
            $step = $row['totp_enabled_at'] !== null && preg_match('/^\d{6}$/', $code) === 1
                ? \Sentinel\Auth\Totp::verify(App::crypto()->decrypt((string) $row['totp_secret_enc']), $code, $row['totp_last_step'] === null ? null : (int) $row['totp_last_step'])
                : null;
            $ok = $step !== null && App::users()->claimTotpStep($id, $step);
        }
        if (!$ok) {
            $this->audit($request, 'system.update_denied', null, null, ['reason' => 'password or 2FA code incorrect']);
            Session::flash('danger', __('The password or the two-factor code is not correct.'));
            return $back;
        }
        App::limiter()->clear($bucket);
        if (!App::webUpdate()->request()) {
            $this->audit($request, 'system.update_denied', null, null, ['reason' => App::webUpdate()->available() ? 'already waiting or running' : 'not set up on this server']);
            Session::flash('warning', App::webUpdate()->available()
                ? __('An update is already waiting or running.')
                : __('Updating from the web interface is not set up on this server. Run sudo msp-sentinel-update on the server.'));
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

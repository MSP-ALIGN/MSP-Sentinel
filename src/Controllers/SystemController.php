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
            'newer' => App::updates()->newer(),
            'updateEnabled' => $s->get('update_check_enabled') === '1',
            'checkedAt' => $s->get('update_checked_at'),
            'retention' => ['scans' => $s->get('retention_scans_months'), 'findings' => $s->get('retention_findings_months'), 'reports' => $s->get('retention_reports_months')],
            'retentionLast' => $s->get('retention_last_run'),
            'sourceUrl' => $s->get('source_url'),
        ]);
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

<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;

/**
 * Global scanning kill switch.
 *
 * Access (enforced by the routes): technicians and admins can pause; only
 * admins can resume.
 *
 * Untrusted: the optional reason field.
 *
 * Security assumptions: pausing takes effect for every scope check straight
 * away (ScopeService reads the setting each time). Both actions are audited.
 */
final class ScanningController extends Controller
{
    /** POST /scanning/pause */
    public function pause(Request $request): Response
    {
        App::settings()->set('scanning_paused', '1');
        $this->audit($request, 'scanning.global_paused', null, null, ['reason' => mb_substr($request->input('reason'), 0, 300)]);
        Session::flash('warning', __('All scanning is paused. It stays paused until someone whose role can resume scanning resumes it.'));
        return Response::redirect('/');
    }

    /** POST /scanning/resume */
    public function resume(Request $request): Response
    {
        App::settings()->set('scanning_paused', '0');
        $this->audit($request, 'scanning.global_resumed');
        Session::flash('success', __('Scanning resumed.'));
        return Response::redirect('/');
    }
}

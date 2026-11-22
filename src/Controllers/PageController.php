<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;

/**
 * Simple read-only pages: dashboard and help.
 *
 * Security assumptions: no input is used apart from the signed-in user.
 * Help entries are trusted text shipped with the app, and are still
 * escaped in the view.
 */
final class PageController extends Controller
{
    /** GET / */
    public function dashboard(Request $request): Response
    {
        $db = App::db();
        $clients = (int) $db->query('SELECT COUNT(*) FROM clients WHERE is_archived = 0')->fetchColumn();
        // Authorisations valid today (UTC date: a summary only; exact per-client checks use each client's timezone).
        $active = (int) $db->query('SELECT COUNT(*) FROM scan_authorisations a JOIN clients c ON c.id = a.client_id AND c.is_archived = 0
                                    WHERE a.revoked_at IS NULL AND a.valid_from <= UTC_DATE() AND a.valid_until >= UTC_DATE()')->fetchColumn();
        $expiring = (int) $db->query('SELECT COUNT(*) FROM scan_authorisations a JOIN clients c ON c.id = a.client_id AND c.is_archived = 0
                                      WHERE a.revoked_at IS NULL AND a.valid_until BETWEEN UTC_DATE() AND UTC_DATE() + INTERVAL 30 DAY')->fetchColumn();
        return $this->page('dashboard', __('Dashboard'), [
            'version' => App::version(),
            'clientCount' => $clients,
            'activeAuthorisations' => $active,
            'expiringAuthorisations' => $expiring,
            'globallyPaused' => App::scope()->globallyPaused(),
            'expiringCerts' => App::endpoints()->countExpiring(\Sentinel\Scanning\ExposureRules::EXPIRY_WARN_DAYS),
            'kevCounts' => App::vulns()->kevCounts(),
        ]);
    }

    /** GET /help */
    public function help(Request $request): Response
    {
        $entries = require SENTINEL_ROOT . '/help/entries.php';
        return $this->page('help/index', __('Help'), ['entries' => is_array($entries) ? $entries : []]);
    }
}

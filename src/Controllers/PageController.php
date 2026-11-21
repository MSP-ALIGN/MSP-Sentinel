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
        return $this->page('dashboard', __('Dashboard'), ['version' => App::version()]);
    }

    /** GET /help */
    public function help(Request $request): Response
    {
        $entries = require SENTINEL_ROOT . '/help/entries.php';
        return $this->page('help/index', __('Help'), ['entries' => is_array($entries) ? $entries : []]);
    }
}

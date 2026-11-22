<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Inventory\InventoryException;
use Sentinel\Inventory\NinjaOneSource;

/**
 * Administration > Integrations: outside systems Sentinel reads from. First: NinjaOne (read-only inventory).
 *
 * Every route is admin-only (src/routes.php) and every POST is CSRF-checked (App::dispatch).
 *
 * Untrusted input: the form fields. The instance must be a *.ninjarmm.com host name (so the secret can only
 * be sent to NinjaOne), the client ID is limited in length and characters, and the secret is stored encrypted
 * with the app key, never shown again, never logged or audited (only "changed" or "cleared").
 */
final class IntegrationsController extends Controller
{
    /** GET /admin/integrations */
    public function index(Request $request): Response
    {
        $s = App::settings();
        return $this->page('admin/integrations', __('Integrations'), [
            'ninja' => [
                'enabled' => $s->get('ninjaone_enabled') === '1',
                'host' => $s->get('ninjaone_host'),
                'client_id' => $s->get('ninjaone_client_id'),
                'has_secret' => $s->getSecret('ninjaone_client_secret') !== '',
                'tested_at' => $s->get('ninjaone_tested_at'),
                'test_result' => $s->get('ninjaone_test_result'),
                'linked' => (int) App::db()->query("SELECT COUNT(*) FROM source_links WHERE source = 'ninjaone'")->fetchColumn(),
            ],
        ]);
    }

    /** POST /admin/integrations/ninjaone: save the NinjaOne settings. */
    public function saveNinjaOne(Request $request): Response
    {
        $back = Response::redirect('/admin/integrations#ninjaone');
        $s = App::settings();
        $host = strtolower(trim($request->input('host')));
        $host = (string) preg_replace('#^https?://|/.*$#', '', $host); // a pasted URL becomes its host name
        $clientId = trim($request->input('client_id'));
        $enabled = $request->input('enabled') === '1';
        if ($host !== '' && !NinjaOneSource::validHost($host)) {
            Session::flash('danger', __('The NinjaOne instance must be the address you sign in at, ending in .ninjarmm.com (for example app.ninjarmm.com or eu.ninjarmm.com).'));
            return $back;
        }
        if ($clientId !== '' && preg_match('/^[A-Za-z0-9._~-]{4,200}$/', $clientId) !== 1) {
            Session::flash('danger', __('The client ID has unexpected characters. Copy it again from NinjaOne.'));
            return $back;
        }
        $oldHost = $s->get('ninjaone_host');
        $changed = [];
        foreach (['ninjaone_host' => $host, 'ninjaone_client_id' => $clientId, 'ninjaone_enabled' => $enabled ? '1' : '0'] as $key => $value) {
            if ($s->get($key) !== $value) {
                $s->set($key, $value);
                $changed[$key] = $key === 'ninjaone_enabled' ? $enabled : $value;
            }
        }
        $secret = $request->raw('client_secret');
        if ($request->input('clear_secret') === '1') {
            $s->setSecret('ninjaone_client_secret', '');
            $changed['ninjaone_client_secret'] = 'cleared';
        } elseif ($secret !== '') {
            if (strlen($secret) > 500 || preg_match('/[\x00-\x1F\x7F]/', $secret) === 1) {
                Session::flash('danger', __('The client secret has unexpected characters. Copy it again from NinjaOne.'));
                return $back;
            }
            $s->setSecret('ninjaone_client_secret', $secret);
            $changed['ninjaone_client_secret'] = 'changed';
        }
        if ($changed !== []) {
            $s->set('ninjaone_test_result', ''); // an old test result no longer says anything
            $this->audit($request, 'settings.ninjaone_updated', null, null, ['changed' => $changed]);
        }
        $linked = (int) App::db()->query("SELECT COUNT(*) FROM source_links WHERE source = 'ninjaone'")->fetchColumn();
        if ($oldHost !== '' && $host !== $oldHost && $linked > 0) {
            // Organisation IDs belong to one NinjaOne account: links made against another one would point at the wrong data.
            Session::flash('warning', __('The NinjaOne instance changed while {n} client(s) are linked. If this is a different NinjaOne account, unlink and link those clients again: their organisation IDs belong to the old one.', ['n' => $linked]));
        }
        $ready = App::ninjaOne() !== null;
        Session::flash($enabled && !$ready ? 'warning' : 'success', $enabled && !$ready
            ? __('Saved, but NinjaOne needs the instance, client ID and client secret before it can sync.')
            : __('NinjaOne settings saved.'));
        return $back;
    }

    /** POST /admin/integrations/ninjaone/test: sign in and count organisations (no data is stored). */
    public function testNinjaOne(Request $request): Response
    {
        $back = Response::redirect('/admin/integrations#ninjaone');
        $source = App::ninjaOne();
        if ($source === null) {
            Session::flash('warning', __('Fill in the instance, client ID and client secret first.'));
            return $back;
        }
        @set_time_limit(60);
        $s = App::settings();
        $ok = false;
        try {
            $count = $source->testConnection();
            $ok = true;
            $result = __('Connected: the API app can see {n} organisation(s).', ['n' => $count]);
            Session::flash('success', $result);
        } catch (InventoryException $ex) {
            $result = __('Failed: {e}', ['e' => $ex->getMessage()]);
            Session::flash('danger', $result);
        }
        $s->set('ninjaone_tested_at', gmdate('Y-m-d H:i:s'));
        $s->set('ninjaone_test_result', mb_substr($result, 0, 500));
        $this->audit($request, 'settings.ninjaone_tested', null, null, ['ok' => $ok]);
        return $back;
    }
}

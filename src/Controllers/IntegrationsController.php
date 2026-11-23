<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Compliance\AlignClient;
use Sentinel\Compliance\AlignException;
use Sentinel\Inventory\InventoryException;
use Sentinel\Inventory\NinjaOneSource;

/**
 * Administration > Integrations: outside systems Sentinel works with: ITFlow (clients sync from it; tickets follow in
 * later phases), NinjaOne (read-only inventory) and MSP Align (read-only compliance, shown on each client's Compliance
 * page).
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
            'itflow' => [
                'enabled' => $s->get('itflow_enabled') === '1',
                'url' => $s->get('itflow_url'),
                'has_key' => $s->getSecret('itflow_api_key') !== '',
                'tested_at' => $s->get('itflow_tested_at'),
                'test_result' => $s->get('itflow_test_result'),
                'last_sync' => $s->get('itflow_last_sync'),
                'last_result' => $s->get('itflow_last_result'),
                'last_ok' => $s->get('itflow_last_ok') !== '0',
                'linked' => (int) App::db()->query('SELECT COUNT(*) FROM clients WHERE itflow_client_id IS NOT NULL AND is_demo = 0')->fetchColumn(),
                'tickets' => $s->get('itflow_tickets_enabled') === '1',
                'tickets_last_run' => $s->get('itflow_tickets_last_run'),
                'tickets_last_result' => $s->get('itflow_tickets_last_result'),
                'tickets_last_ok' => $s->get('itflow_tickets_last_ok') !== '0',
                'tickets_total' => (int) App::db()->query('SELECT COUNT(*) FROM itflow_tickets')->fetchColumn(),
            ],
            'align' => [
                'enabled' => $s->get('mspalign_enabled') === '1',
                'url' => $s->get('mspalign_url'),
                'has_key' => $s->getSecret('mspalign_api_key') !== '',
                'tested_at' => $s->get('mspalign_tested_at'),
                'test_result' => $s->get('mspalign_test_result'),
                'linked' => (int) App::db()->query('SELECT COUNT(*) FROM clients WHERE align_client_id IS NOT NULL')->fetchColumn(),
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

    /** POST /admin/integrations/mspalign: save the MSP Align address, API key and on/off. */
    public function saveAlign(Request $request): Response
    {
        $back = Response::redirect('/admin/integrations#mspalign');
        $s = App::settings();
        $url = rtrim(trim($request->input('url')), '/');
        $url = (string) preg_replace('#/api/v1$#', '', $url); // a pasted API address becomes the app address
        $enabled = $request->input('enabled') === '1';
        if ($url !== '' && !AlignClient::validUrl($url, App::webhookTestMode())) {
            Session::flash('danger', __('The MSP Align address must be an https:// address, for example https://align.msp.example.'));
            return $back;
        }
        $changed = [];
        foreach (['mspalign_url' => $url, 'mspalign_enabled' => $enabled ? '1' : '0'] as $key => $value) {
            if ($s->get($key) !== $value) {
                $s->set($key, $value);
                $changed[$key] = $key === 'mspalign_enabled' ? $enabled : $value;
            }
        }
        $apiKey = trim($request->raw('api_key'));
        if ($request->input('clear_key') === '1') {
            $s->setSecret('mspalign_api_key', '');
            $changed['mspalign_api_key'] = 'cleared';
        } elseif ($apiKey !== '') {
            if (!AlignClient::validKey($apiKey)) {
                Session::flash('danger', __('That is not an MSP Align API key (they look like msa_xxxxxxxx_...). Create one in MSP Align under Settings, API.'));
                return $back;
            }
            $s->setSecret('mspalign_api_key', $apiKey);
            $changed['mspalign_api_key'] = 'changed';
        }
        if ($changed !== []) {
            $s->set('mspalign_test_result', '');
            App::db()->exec('DELETE FROM align_cache'); // another address or key: read everything again
            $s->set('mspalign_clients_cache', '');
            $this->audit($request, 'settings.mspalign_updated', null, null, ['changed' => $changed]);
        }
        Session::flash('success', __('MSP Align settings saved.'));
        return $back;
    }

    /** POST /admin/integrations/mspalign/test: read the key's description and check its permissions. */
    public function testAlign(Request $request): Response
    {
        $back = Response::redirect('/admin/integrations#mspalign');
        $align = App::align(true);
        if ($align === null) {
            Session::flash('warning', __('Fill in the MSP Align address and API key first.'));
            return $back;
        }
        $ok = false;
        try {
            $me = $align->whoami();
            $missing = array_values(array_diff(['clients:read', 'compliance:read'], self::expand($me['scopes'])));
            $writes = array_values(array_filter($me['scopes'], static fn (string $sc): bool => str_ends_with($sc, ':write')));
            if ($missing !== []) {
                $result = __('Connected, but the key is missing {list}. Give it clients:read and compliance:read in MSP Align.', ['list' => implode(', ', $missing)]);
            } else {
                $ok = true;
                $result = __('Connected to MSP Align {v} as "{name}"; the key can see {n} client(s).', ['v' => $me['app_version'], 'name' => $me['name'], 'n' => count($align->clients())])
                    . ($writes !== [] ? ' ' . __('Tip: Sentinel only reads, so a key without write permissions ({list}) is safer.', ['list' => implode(', ', $writes)]) : '');
            }
        } catch (AlignException $ex) {
            $result = __('Failed: {e}', ['e' => $ex->getMessage()]);
        }
        Session::flash($ok ? 'success' : 'danger', $result);
        App::settings()->set('mspalign_tested_at', gmdate('Y-m-d H:i:s'));
        App::settings()->set('mspalign_test_result', mb_substr($result, 0, 500));
        $this->audit($request, 'settings.mspalign_tested', null, null, ['ok' => $ok]);
        return $back;
    }

    /** POST /admin/integrations/itflow: save the ITFlow address, API key and on/off. */
    public function saveItflow(Request $request): Response
    {
        $back = Response::redirect('/admin/integrations#itflow');
        $s = App::settings();
        $url = rtrim(trim($request->input('url')), '/');
        $url = (string) preg_replace('#/api(/v1)?$#', '', $url); // a pasted API address becomes ITFlow's address
        $enabled = $request->input('enabled') === '1';
        if ($url !== '' && !\Sentinel\Itflow\ItflowClient::validUrl($url, App::webhookTestMode())) {
            Session::flash('danger', __('The ITFlow address must be an https:// address, for example https://itflow.msp.example.'));
            return $back;
        }
        $changed = [];
        $tickets = $request->input('tickets') === '1';
        if ($tickets && $s->get('itflow_tickets_enabled') !== '1') {
            $s->set('itflow_tickets_since', gmdate('Y-m-d H:i:s')); // only findings from now on (no flood when turning it on)
        }
        foreach (['itflow_url' => $url, 'itflow_enabled' => $enabled ? '1' : '0', 'itflow_tickets_enabled' => $tickets ? '1' : '0'] as $key => $value) {
            if ($s->get($key) !== $value) {
                $s->set($key, $value);
                $changed[$key] = in_array($key, ['itflow_enabled', 'itflow_tickets_enabled'], true) ? $value === '1' : $value;
            }
        }
        $apiKey = trim($request->raw('api_key'));
        if ($request->input('clear_key') === '1') {
            $s->setSecret('itflow_api_key', '');
            $changed['itflow_api_key'] = 'cleared';
        } elseif ($apiKey !== '') {
            if (!\Sentinel\Itflow\ItflowClient::validKey($apiKey)) {
                Session::flash('danger', __('That does not look like an ITFlow API key. Copy it again from ITFlow (Admin, API Keys).'));
                return $back;
            }
            $s->setSecret('itflow_api_key', $apiKey);
            $changed['itflow_api_key'] = 'changed';
        }
        if ($changed !== []) {
            $s->set('itflow_test_result', '');
            $this->audit($request, 'settings.itflow_updated', null, null, ['changed' => $changed]);
        }
        Session::flash('success', $enabled ? __('ITFlow settings saved. Clients sync within 15 minutes, or use Sync now.') : __('ITFlow settings saved.'));
        return $back;
    }

    /** POST /admin/integrations/itflow/test: read ITFlow's clients (nothing is changed). */
    public function testItflow(Request $request): Response
    {
        $back = Response::redirect('/admin/integrations#itflow');
        $itflow = App::itflow();
        if ($itflow === null) {
            Session::flash('warning', __('Fill in the ITFlow address and API key first.'));
            return $back;
        }
        @set_time_limit(60);
        $ok = false;
        try {
            $clients = $itflow->clients();
            $active = count(array_filter($clients, static fn (array $c): bool => !$c['archived']));
            $result = __('Connected: the key can see {n} client(s) in ITFlow ({a} active).', ['n' => count($clients), 'a' => $active]);
            $ok = true;
        } catch (\Sentinel\Itflow\ItflowException $ex) {
            $result = __('Failed: {e}', ['e' => $ex->getMessage()]);
        }
        Session::flash($ok ? 'success' : 'danger', $result);
        App::settings()->set('itflow_tested_at', gmdate('Y-m-d H:i:s'));
        App::settings()->set('itflow_test_result', mb_substr($result, 0, 500));
        $this->audit($request, 'settings.itflow_tested', null, null, ['ok' => $ok]);
        return $back;
    }

    /** POST /admin/integrations/itflow/sync: sync clients now. */
    public function syncItflow(Request $request): Response
    {
        $back = Response::redirect('/admin/integrations#itflow');
        if (App::itflow() === null || App::settings()->get('itflow_enabled') !== '1') {
            Session::flash('warning', __('Turn on the ITFlow client sync and save first.'));
            return $back;
        }
        @set_time_limit(120);
        $summary = App::itflowSync()->sync();
        $this->audit($request, 'itflow.sync_requested', null, null, ['result' => mb_substr($summary, 0, 300)]);
        Session::flash(str_starts_with($summary, 'Failed') ? 'danger' : 'success', __('ITFlow sync: {s}', ['s' => $summary]));
        return $back;
    }

    /**
     * POST /admin/integrations/itflow/tickets: open due tickets now; with existing=1 first include the open Fail findings
     * that were there before tickets were turned on (the rest follow every 5 minutes, MAX_PER_RUN at a time).
     */
    public function ticketsItflow(Request $request): Response
    {
        $back = Response::redirect('/admin/integrations#itflow');
        if (App::itflow() === null || App::settings()->get('itflow_tickets_enabled') !== '1') {
            Session::flash('warning', __('Turn on ITFlow tickets and save first.'));
            return $back;
        }
        if ($request->input('existing') === '1') {
            App::settings()->set('itflow_tickets_since', '2000-01-01 00:00:00');
            $this->audit($request, 'itflow.tickets_for_existing');
        }
        @set_time_limit(120);
        $summary = App::itflowTickets()->run();
        Session::flash(str_contains($summary, 'Stopped:') ? 'danger' : 'success', __('ITFlow tickets: {s}', ['s' => $summary]));
        return $back;
    }

    /**
     * MSP Align scopes with write implying read (as MSP Align itself treats them).
     *
     * @param list<string> $scopes
     * @return list<string>
     */
    private static function expand(array $scopes): array
    {
        $out = $scopes;
        foreach ($scopes as $sc) {
            if (str_ends_with($sc, ':write')) {
                $out[] = substr($sc, 0, -6) . ':read';
            }
        }
        return array_values(array_unique($out));
    }
}

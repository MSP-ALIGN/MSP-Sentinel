<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Core\HttpException;
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
                'tag_filter' => $s->get('itflow_tag_filter') === '1',
                'tag_name' => $s->get('itflow_tag_name'),
                'sync_off' => (int) App::db()->query('SELECT COUNT(*) FROM clients WHERE itflow_sync_off = 1 AND is_demo = 0')->fetchColumn(),
                // Service boards (1.44, ITFlow builds with boards); null: this ITFlow has none, or isn't reachable now.
                'board' => $s->get('itflow_board'),
                // The list kept by the last sync, test or ticket run: the page never waits on ITFlow (1.44.1).
                'boards' => (static function () use ($s): ?array {
                    $c = json_decode($s->get('itflow_boards_cache'), true);
                    return is_array($c) ? array_values(array_filter($c, static fn ($b): bool => is_array($b) && is_int($b['id'] ?? null) && is_string($b['name'] ?? null))) : null;
                })(),
                'boards_checked' => $s->get('itflow_boards_cache') !== '',
                'tickets_last_run' => $s->get('itflow_tickets_last_run'),
                'tickets_last_result' => $s->get('itflow_tickets_last_result'),
                'tickets_last_ok' => $s->get('itflow_tickets_last_ok') !== '0',
                'tickets_total' => (int) App::db()->query('SELECT COUNT(*) FROM itflow_tickets')->fetchColumn(),
            ],
            'sso' => [
                'enabled' => $s->get('sso_entra_enabled') === '1',
                'tenant' => $s->get('sso_entra_tenant'),
                'client' => $s->get('sso_entra_client'),
                'has_secret' => $s->getSecret('sso_entra_secret') !== '',
                'redirect' => App::ssoRedirectUri(),
                'linked' => (int) App::db()->query('SELECT COUNT(*) FROM users WHERE sso_subject IS NOT NULL')->fetchColumn(),
            ],
            'breach' => [
                'enabled' => $s->get('breach_enabled') === '1',
                'has_key' => $s->getSecret('xon_api_key') !== '',
                'last_run' => $s->get('breach_last_run'),
                'last_result' => $s->get('breach_last_result'),
                'last_ok' => $s->get('breach_last_ok') !== '0',
                'unmatched' => array_values(array_filter(explode(',', $s->get('breach_unmatched')))),
                'addresses' => (int) App::db()->query('SELECT COUNT(*) FROM breach_exposures')->fetchColumn(),
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

    /**
     * POST /admin/integrations/sso: Sign in with Microsoft (1.43): the Entra tenant ID, application (client) ID and
     * client secret, and on/off. Untrusted: every field (IDs must be GUIDs; the secret is stored encrypted, never
     * shown again). Turning it on needs Sentinel's public address (app.public_url) for Microsoft's redirect.
     */
    public function saveSso(Request $request): Response
    {
        $back = Response::redirect('/admin/integrations#sso');
        // Whoever controls sign-in could sign in as anyone linked to it: only someone who holds every permission and
        // sees every client sets it, with their own password (1.43.1).
        if (!\Sentinel\Auth\Permissions::isComplete((array) ($this->user()['permissions'] ?? [])) || ($this->user()['client_ids'] ?? null) !== null) {
            throw new HttpException(403, __('Only someone who holds every permission (an Admin) and sees every client can change Sign in with Microsoft.'));
        }
        if (($why = $this->confirmWithOwnPassword($request)) !== null) {
            Session::flash('danger', $why);
            return $back;
        }
        $s = App::settings();
        $tenant = strtolower(trim($request->input('tenant_id')));
        $client = strtolower(trim($request->input('client_id')));
        $secret = trim($request->raw('client_secret'));
        $enabled = $request->input('enabled') === '1';
        if (($tenant !== '' && !\Sentinel\Auth\EntraSso::validGuid($tenant)) || ($client !== '' && !\Sentinel\Auth\EntraSso::validGuid($client))) {
            Session::flash('danger', __('The tenant ID and application (client) ID are GUIDs, e.g. 00000000-0000-0000-0000-000000000000 (from the app registration\'s Overview page).'));
            return $back;
        }
        if ($secret !== '' && (strlen($secret) > 200 || preg_match('/[\x00-\x1F\x7F]/', $secret) === 1)) {
            Session::flash('danger', __('That client secret is not valid. Copy its Value (not its ID) from Certificates & secrets.'));
            return $back;
        }
        $changed = [];
        // Another tenant means other accounts: every link to the old one is cleared (users link again from My profile).
        if ($s->get('sso_entra_tenant') !== $tenant && $s->get('sso_entra_tenant') !== '') {
            $cleared = App::db()->exec('UPDATE users SET sso_subject = NULL WHERE sso_subject IS NOT NULL');
            $changed['links_cleared'] = (int) $cleared;
        }
        foreach (['sso_entra_tenant' => $tenant, 'sso_entra_client' => $client] as $name => $value) {
            if ($s->get($name) !== $value) {
                $s->set($name, $value);
                $changed[$name] = $value;
            }
        }
        if ($request->input('clear_secret') === '1') {
            $s->setSecret('sso_entra_secret', '');
            $changed['sso_entra_secret'] = 'cleared';
        } elseif ($secret !== '') {
            $s->setSecret('sso_entra_secret', $secret);
            $changed['sso_entra_secret'] = 'changed';
        }
        if ($enabled && (App::ssoRedirectUri() === '' || $s->get('sso_entra_tenant') === '' || $s->get('sso_entra_client') === '' || $s->getSecret('sso_entra_secret') === '')) {
            $enabled = false;
            Session::flash('warning', __('Not turned on yet: it needs the tenant ID, application (client) ID, client secret, and Sentinel\'s public address (app.public_url in the config file).'));
        }
        if ($s->get('sso_entra_enabled') !== ($enabled ? '1' : '0')) {
            $s->set('sso_entra_enabled', $enabled ? '1' : '0');
            $changed['sso_entra_enabled'] = $enabled;
        }
        if ($changed !== []) {
            $this->audit($request, 'settings.sso_updated', null, null, ['changed' => $changed]);
        }
        Session::flash('success', __('Sign in with Microsoft settings saved.'));
        return $back;
    }

    /** POST /admin/integrations/breach: save the XposedOrNot API key and on/off (breach monitoring, 1.33). */
    public function saveBreach(Request $request): Response
    {
        $back = Response::redirect('/admin/integrations#breach');
        $s = App::settings();
        $enabled = $request->input('enabled') === '1';
        $changed = [];
        if ($s->get('breach_enabled') !== ($enabled ? '1' : '0')) {
            $s->set('breach_enabled', $enabled ? '1' : '0');
            $changed['breach_enabled'] = $enabled;
        }
        $apiKey = trim($request->raw('api_key'));
        if ($request->input('clear_key') === '1') {
            $s->setSecret('xon_api_key', '');
            $changed['xon_api_key'] = 'cleared';
        } elseif ($apiKey !== '') {
            if (!\Sentinel\Breach\XonClient::validKey($apiKey)) {
                Session::flash('danger', __('That doesn\'t look like an XposedOrNot API key. Copy it from your XposedOrNot dashboard (API Key Management).'));
                return $back;
            }
            $s->setSecret('xon_api_key', $apiKey);
            $changed['xon_api_key'] = 'changed';
            $s->set('breach_last_run', ''); // a new key may be checked at once (and the weekly check starts again)
            $s->set('breach_last_ok_run', '');
        }
        if ($changed !== []) {
            $this->audit($request, 'settings.breach_updated', null, null, ['changed' => $changed]);
        }
        Session::flash('success', __('Breach monitoring settings saved.'));
        return $back;
    }

    /** POST /admin/integrations/breach/check: check now (at most once an hour: the provider allows few calls a day). */
    public function checkBreach(Request $request): Response
    {
        $back = Response::redirect('/admin/integrations#breach');
        $s = App::settings();
        if ($s->getSecret('xon_api_key') === '') {
            Session::flash('warning', __('Save an XposedOrNot API key first.'));
            return $back;
        }
        $last = $s->fresh('breach_last_run');
        if ($last !== '' && strtotime($last . ' UTC') > time() - 3600) {
            Session::flash('warning', __('Checked less than an hour ago. Try again later (the provider allows only a few checks a day).'));
            return $back;
        }
        $summary = App::breachMonitor()->run();
        $this->audit($request, 'breach.check_requested', null, null, []);
        Session::flash(str_starts_with($summary, 'Stopped') ? 'warning' : 'success', $summary);
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
        // Everything is checked before anything is saved (1.34 audit: a bad key must not leave a new address saved
        // with the old key).
        $apiKey = trim($request->raw('api_key'));
        if ($apiKey !== '' && $request->input('clear_key') !== '1' && !AlignClient::validKey($apiKey)) {
            Session::flash('danger', __('That is not an MSP Align API key (they look like msa_xxxxxxxx_...). Create one in MSP Align under Settings, API.'));
            return $back;
        }
        $changed = [];
        // A saved key never follows a new address (see saveItflow).
        $alignDropped = $s->get('mspalign_url') !== $url && $s->getSecret('mspalign_api_key') !== '' && trim($request->raw('api_key')) === '';
        if ($alignDropped) {
            $s->setSecret('mspalign_api_key', '');
            $changed['mspalign_api_key'] = 'cleared (address changed)';
            Session::flash('warning', __('The MSP Align address changed, so the saved API key was removed. Enter the key again for the new address.'));
        }
        foreach (['mspalign_url' => $url, 'mspalign_enabled' => $enabled ? '1' : '0'] as $key => $value) {
            if ($s->get($key) !== $value) {
                $s->set($key, $value);
                $changed[$key] = $key === 'mspalign_enabled' ? $enabled : $value;
            }
        }
        if ($request->input('clear_key') === '1') {
            $s->setSecret('mspalign_api_key', '');
            $changed['mspalign_api_key'] = 'cleared';
        } elseif ($apiKey !== '') {
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
        // Everything is checked before anything is saved (1.34 audit, see saveAlign).
        $apiKey = trim($request->raw('api_key'));
        if ($apiKey !== '' && $request->input('clear_key') !== '1' && !\Sentinel\Itflow\ItflowClient::validKey($apiKey)) {
            Session::flash('danger', __('That does not look like an ITFlow API key. Copy it again from ITFlow (Admin, API Keys).'));
            return $back;
        }
        // Only clients with this ITFlow tag (1.45). Untrusted: a short name without control characters.
        $tagFilter = $request->input('tag_filter') === '1';
        $tagName = trim($request->input('tag_name'));
        if ($tagName === '') {
            $tagName = 'Sentinel';
        }
        if (!mb_check_encoding($tagName, 'UTF-8') || mb_strlen($tagName) > 100 || preg_match('/\p{C}/u', $tagName) !== 0) {
            Session::flash('danger', __('The ITFlow tag name can be at most 100 characters, without line breaks.'));
            return $back;
        }
        $changed = [];
        // A saved key never follows a new address: a changed address needs the key entered again (so a typo, a hijacked
        // session or a rogue admin can't send the stored key to another server).
        $keyDropped = $s->get('itflow_url') !== $url && $s->getSecret('itflow_api_key') !== '' && trim($request->raw('api_key')) === '';
        if ($keyDropped) {
            $s->setSecret('itflow_api_key', '');
            $changed['itflow_api_key'] = 'cleared (address changed)';
        }
        $tickets = $request->input('tickets') === '1';
        if ($tickets && $s->get('itflow_tickets_enabled') !== '1') {
            $s->set('itflow_tickets_since', gmdate('Y-m-d H:i:s')); // only findings from now on (no flood when turning it on)
            $s->set('itflow_tickets_weekly_since', gmdate('Y-m-d H:i:s'));
        }
        // The board for new tickets (1.44): '' = the one named Alerts, '0' = ITFlow's default, else a board ID. Untrusted.
        $board = $request->input('board');
        if (!preg_match('/^(|0|[1-9][0-9]{0,9})$/', $board)) {
            $board = $s->get('itflow_board');
        }
        if ($board !== $s->get('itflow_board')) {
            $s->set('itflow_board', $board);
            $changed['itflow_board'] = $board;
        }
        foreach (['itflow_url' => $url, 'itflow_enabled' => $enabled ? '1' : '0', 'itflow_tickets_enabled' => $tickets ? '1' : '0',
                  'itflow_tag_filter' => $tagFilter ? '1' : '0', 'itflow_tag_name' => $tagName] as $key => $value) {
            if ($s->get($key) !== $value) {
                $s->set($key, $value);
                $changed[$key] = in_array($key, ['itflow_enabled', 'itflow_tickets_enabled', 'itflow_tag_filter'], true) ? $value === '1' : $value;
            }
        }
        if ($request->input('clear_key') === '1') {
            $s->setSecret('itflow_api_key', '');
            $changed['itflow_api_key'] = 'cleared';
        } elseif ($apiKey !== '') {
            $s->setSecret('itflow_api_key', $apiKey);
            $changed['itflow_api_key'] = 'changed';
        }
        if ($changed !== []) {
            $s->set('itflow_test_result', '');
            $this->audit($request, 'settings.itflow_updated', null, null, ['changed' => $changed]);
        }
        if ($keyDropped) {
            Session::flash('warning', __('The ITFlow address changed, so the saved API key was removed. Enter the key again for the new address.'));
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
            try {
                $boards = $itflow->refreshBoards(App::settings()); // also refresh the board list for the drop-down (1.44.1)
                if ($boards !== null) {
                    $result .= ' ' . __('{n} service board(s).', ['n' => count($boards)]);
                }
            } catch (\Sentinel\Itflow\ItflowException $ex) {
                $result .= ' ' . __('Boards could not be read: {e}', ['e' => $ex->getMessage()]);
            }
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
     * that were there before tickets were turned on (the rest follow every 5 minutes, MAX_PER_RUN at a time). Weekly
     * Warnings tickets keep their own start (itflow_tickets_weekly_since), so this never sends every client one.
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

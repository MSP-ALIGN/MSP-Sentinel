<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Agent\DirectoryRepository;
use Sentinel\Agent\InternalRanges;
use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Scope\ScopeService;

/**
 * Active Directory checks of a site (on the client's Agents page): the domain, its domain controller, the read-only
 * account, the password (sealed in the browser to the site's agent: this controller only ever sees the sealed box),
 * trusting the domain controller's certificate, and turning the checks off.
 *
 * Access (enforced by the routes): admins only; every POST is CSRF-checked by the router.
 *
 * Untrusted: {id} and {site} (the site must belong to the client); every form value. The domain controller must be
 * an address inside the site's signed internal authorisation (the agent checks that again). A plain password field is
 * never read: the form has none with a name; only "sealed" (shape and size checked, unreadable here) is used.
 *
 * Security assumptions: the sealed box is bound to the agent, a fresh nonce and the user name (AgentKey::directoryAad),
 * so it can't be replayed to another agent or for another account. Every change is audited (never the box itself).
 */
final class DirectoryController extends Controller
{
    /** POST /clients/{id}/sites/{site}/directory: save the settings, and the sealed password when one was entered. */
    public function save(Request $request, array $params): Response
    {
        [$client, $site] = $this->clientSite($params);
        $back = Response::redirect('/clients/' . (int) $client['id'] . '/agents#directory-' . (int) $site['id']);
        $domain = strtolower(trim($request->input('domain'), " .\t"));
        $dcIp = trim($request->input('dc_ip'));
        $username = trim($request->input('username'));
        $sealed = $request->raw('sealed');
        $nonce = $request->input('nonce');
        $auth = App::agents()->activeAuthorisation((int) $site['id'], ScopeService::today((string) $client['timezone']));
        $error = match (true) {
            (int) ($client['is_demo'] ?? 0) === 1 => __('This is a demo client with made-up data: it is never scanned.'),
            preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/', $domain) !== 1 => __('Enter the Active Directory domain name, for example corp.example.'),
            filter_var($dcIp, FILTER_VALIDATE_IP) === false => __('Enter the domain controller\'s IP address.'),
            $auth === null => __('This site has no valid internal authorisation.'),
            !InternalRanges::allWithin([$dcIp], $auth['ranges_list']) => __('The domain controller must be inside the site\'s internal authorisation ({ranges}).', ['ranges' => implode(', ', $auth['ranges_list'])]),
            $username === '' || strlen($username) > 256 || preg_match('/[\x00-\x1F\x7F]/', $username) === 1 || preg_match('/^[^@\\\\\s]+(@[^@\s]+|)$|^[^\\\\\s]+\\\\[^\\\\\s]+$/', $username) !== 1
                => __('Enter the account as user@domain or DOMAIN\\user.'),
            default => null,
        };
        if ($error === null && $sealed !== '') {
            $agent = $this->siteAgent((int) $site['id']);
            $error = match (true) {
                $agent === null => __('This site has no active agent to send the password to.'),
                (string) $agent['box_public_key'] === '' => __('The site\'s agent is too old to receive passwords: update it first.'),
                (int) $request->input('agent_id') !== (int) $agent['id'] => __('The site\'s agent changed while you were typing. Enter the password again.'),
                preg_match('/^[0-9a-f]{32}$/', $nonce) !== 1 || !self::sealedShape($sealed) => __('The password could not be sent sealed. Nothing was saved.'),
                default => null,
            };
        }
        if ($error !== null) {
            Session::flash('danger', $error);
            return $back;
        }
        $repo = App::directory();
        $changed = $repo->saveSettings((int) $site['id'], (int) $client['id'], $domain, $dcIp, $username);
        if ($sealed !== '') {
            $repo->createDrop((int) $this->siteAgent((int) $site['id'])['id'], (int) $site['id'], $nonce, $username, $sealed, (int) $this->user()['id']);
            $changed[] = 'password';
        }
        $this->audit($request, 'site.directory_updated', 'site', (int) $site['id'], ['client_id' => (int) $client['id'], 'changed' => $changed]);
        Session::flash('success', $sealed !== ''
            ? __('Saved. The password was sealed in your browser for the agent; it collects it at its next check-in (within a minute). Sentinel cannot read it.')
            : __('Active Directory settings saved.'));
        return $back;
    }

    /** POST /clients/{id}/sites/{site}/directory/trust: trust the domain controller certificate the agent reported. */
    public function trust(Request $request, array $params): Response
    {
        [$client, $site] = $this->clientSite($params);
        $fingerprint = strtolower($request->input('fingerprint'));
        if (preg_match('/^[0-9a-f]{64}$/', $fingerprint) !== 1 || !App::directory()->trustCertificate((int) $site['id'], $fingerprint, (int) $this->user()['id'])) {
            Session::flash('warning', __('That certificate is no longer the one the agent saw. Check the page again.'));
        } else {
            $this->audit($request, 'site.directory_certificate_trusted', 'site', (int) $site['id'], ['client_id' => (int) $client['id'], 'sha256' => $fingerprint]);
            Session::flash('success', __('Certificate trusted. The agent signs in to the domain controller from its next full scan.'));
        }
        return Response::redirect('/clients/' . (int) $client['id'] . '/agents#directory-' . (int) $site['id']);
    }

    /** POST /clients/{id}/sites/{site}/directory/remove: turn the checks off (the agent is told to delete the password). */
    public function remove(Request $request, array $params): Response
    {
        [$client, $site] = $this->clientSite($params);
        App::directory()->remove((int) $site['id']);
        $this->audit($request, 'site.directory_removed', 'site', (int) $site['id'], ['client_id' => (int) $client['id']]);
        Session::flash('success', __('Active Directory checks turned off. The agent deletes the password at its next check-in.'));
        return Response::redirect('/clients/' . (int) $client['id'] . '/agents');
    }

    /** Whether a string looks like a sealed box from agent-seal.js (it can't be opened here). */
    private static function sealedShape(string $sealed): bool
    {
        if (strlen($sealed) > DirectoryRepository::MAX_SEALED) {
            return false;
        }
        $box = json_decode($sealed, true);
        if (!is_array($box) || ($box['v'] ?? null) !== 1 || count($box) !== 4) {
            return false;
        }
        foreach (['epk' => [60, 200], 'iv' => [12, 12], 'ct' => [17, 3000]] as $k => [$min, $max]) {
            $raw = is_string($box[$k] ?? null) ? base64_decode($box[$k], true) : false;
            if ($raw === false || strlen($raw) < $min || strlen($raw) > $max) {
                return false;
            }
        }
        return true;
    }

    /** The site's active agent (newest), or null. @return array<string,mixed>|null */
    private function siteAgent(int $siteId): ?array
    {
        $stmt = App::db()->prepare("SELECT * FROM agents WHERE site_id = :s AND status = 'active' ORDER BY id DESC LIMIT 1");
        $stmt->execute(['s' => $siteId]);
        $a = $stmt->fetch();
        return $a === false ? null : $a;
    }

    /**
     * The client and one of its sites ({site} must belong to {id}).
     *
     * @return array{0:array<string,mixed>, 1:array<string,mixed>}
     */
    private function clientSite(array $params): array
    {
        $client = App::clients()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
        $stmt = App::db()->prepare('SELECT * FROM sites WHERE id = :s AND client_id = :c');
        $stmt->execute(['s' => (int) ($params['site'] ?? 0), 'c' => (int) $client['id']]);
        $site = $stmt->fetch();
        if ($site === false) {
            throw new HttpException(404);
        }
        return [$client, $site];
    }
}

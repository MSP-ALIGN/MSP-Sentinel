<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Compliance\AlignException;

/**
 * A client's link to its MSP Align client (for the Compliance page). Read-only towards MSP Align.
 *
 * Routes: link and unlink are admin-only, refresh is for technicians and up (src/routes.php); every POST is
 * CSRF-checked (App::dispatch).
 *
 * Untrusted input: align_client_id (digits only, and it must be a client the MSP Align key can see: checked against
 * MSP Align's own list, whose name is stored for display), and the client ID in the path (404 if unknown).
 */
final class ComplianceController extends Controller
{
    /** POST /clients/{id}/compliance/link */
    public function link(Request $request, array $params): Response
    {
        $client = $this->client($params);
        $back = Response::redirect('/clients/' . (int) $client['id'] . '/compliance');
        if ((int) $client['is_archived'] === 1 || (int) ($client['is_demo'] ?? 0) === 1) {
            Session::flash('warning', __('Archived and demo clients can\'t be linked to MSP Align.'));
            return $back;
        }
        $align = App::align();
        $wanted = $request->input('align_client_id');
        if ($align === null || !ctype_digit($wanted) || strlen($wanted) > 10) {
            Session::flash('danger', $align === null ? __('MSP Align is not connected (Administration, Integrations).') : __('Choose an MSP Align client.'));
            return $back;
        }
        try {
            $match = null;
            foreach ($align->clients() as $c) {
                if ($c['id'] === (int) $wanted) {
                    $match = $c;
                }
            }
        } catch (AlignException $ex) {
            Session::flash('danger', $ex->getMessage());
            return $back;
        }
        if ($match === null) {
            Session::flash('danger', __('That MSP Align client is not visible to the API key.'));
            return $back;
        }
        // One MSP Align client per Sentinel client (1.42.1, as for inventory links): otherwise someone could read
        // another client's compliance data through their own client.
        $taken = App::db()->prepare('SELECT COUNT(*) FROM clients WHERE align_client_id = :a AND id <> :id');
        $taken->execute(['a' => $match['id'], 'id' => (int) $client['id']]);
        if ((int) $taken->fetchColumn() > 0) {
            Session::flash('danger', __('That MSP Align client can\'t be linked here: it is already in use. Ask an admin who sees every client.'));
            return $back;
        }
        App::db()->prepare('UPDATE clients SET align_client_id = :a, align_client_name = :n, updated_at = UTC_TIMESTAMP() WHERE id = :id')
            ->execute(['a' => $match['id'], 'n' => mb_substr($match['name'], 0, 190), 'id' => (int) $client['id']]);
        App::db()->prepare('DELETE FROM align_cache WHERE client_id = :c')->execute(['c' => (int) $client['id']]);
        $this->audit($request, 'client.align_linked', 'client', (int) $client['id'], ['align_client_id' => $match['id'], 'align_client_name' => $match['name']]);
        Session::flash('success', __('Linked to {name} in MSP Align.', ['name' => $match['name']]));
        return $back;
    }

    /** POST /clients/{id}/compliance/unlink */
    public function unlink(Request $request, array $params): Response
    {
        $client = $this->client($params);
        App::db()->prepare('UPDATE clients SET align_client_id = NULL, align_client_name = NULL, updated_at = UTC_TIMESTAMP() WHERE id = :id')->execute(['id' => (int) $client['id']]);
        App::db()->prepare('DELETE FROM align_cache WHERE client_id = :c')->execute(['c' => (int) $client['id']]);
        $this->audit($request, 'client.align_unlinked', 'client', (int) $client['id']);
        Session::flash('success', __('Unlinked from MSP Align.'));
        return Response::redirect('/clients/' . (int) $client['id'] . '/compliance');
    }

    /** POST /clients/{id}/compliance/refresh: read MSP Align again now (instead of waiting for the hourly cache). */
    public function refresh(Request $request, array $params): Response
    {
        $client = $this->client($params);
        // At most once a minute per client, so repeated clicks can't use up the MSP Align key's rate limit.
        $last = App::db()->prepare('SELECT GREATEST(fetched_at, COALESCE(attempted_at, fetched_at)) FROM align_cache WHERE client_id = :c');
        $last->execute(['c' => (int) $client['id']]);
        $at = $last->fetchColumn();
        if (is_string($at) && strtotime($at . ' UTC') > time() - 60) {
            Session::flash('info', __('Read from MSP Align less than a minute ago. Try again in a minute.'));
            return Response::redirect('/clients/' . (int) $client['id'] . '/compliance');
        }
        $data = (new \Sentinel\Compliance\AlignCompliance(App::db(), App::align()))->forClient($client, true);
        Session::flash($data['error'] === '' ? 'success' : 'danger', $data['error'] === '' ? __('Compliance read again from MSP Align.') : $data['error']);
        return Response::redirect('/clients/' . (int) $client['id'] . '/compliance');
    }

    /** @param array<string,string> $params @return array<string,mixed> */
    private function client(array $params): array
    {
        return App::clients()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
    }
}

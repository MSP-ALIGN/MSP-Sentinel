<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use DateTimeImmutable;
use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Scope\ScopeService;

/**
 * The "authorised to scan" register: record and revoke authorisations.
 *
 * Access (enforced by the routes): admins only. Everyone signed in can see
 * authorisations on the client page.
 *
 * Untrusted: all form fields (approver details, dates, scope lines) and {id}.
 *
 * Security assumptions:
 * - Nothing outside an active authorisation's scope may ever be scanned.
 *   This form is where that scope is defined, so it is strict: only public
 *   targets, limited range sizes, and validity of 2 years at most.
 * - Authorisations can't be edited, only revoked, so the register stays
 *   trustworthy as evidence. Changing a scope means revoking and recording
 *   a new authorisation.
 * - The admin must tick a confirmation that the client really gave this
 *   authorisation. That is recorded in the audit log.
 */
final class AuthorisationController extends Controller
{

    /**
     * GET /clients/{id}/authorisations/new
     *
     * With ?suggestion[]=ID (approving discovery suggestions) or ?replace=1, the
     * form is pre-filled with the client's current active scope plus the chosen
     * suggestions, and saving it replaces (revokes) the current active
     * authorisations. The approver fields stay empty on purpose: the extra
     * targets need the client's approval too.
     */
    public function create(Request $request, array $params): Response
    {
        $client = $this->clientOr404($params);
        $clientId = (int) $client['id'];
        $today = ScopeService::today((string) $client['timezone']);
        $scope = '';
        $replaces = [];
        $added = [];
        $suggestionIds = array_map('intval', array_filter($request->queryList('suggestion'), 'ctype_digit'));
        if ($suggestionIds !== [] || $request->query('replace') === '1') {
            $lines = [];
            foreach (App::authorisations()->forClient($clientId) as $a) {
                if (ScopeService::status($a, $today) === ScopeService::STATUS_ACTIVE) {
                    $replaces[] = (int) $a['id'];
                    foreach ($a['entries'] as $e) {
                        $lines[(string) $e['value']] = true;
                    }
                }
            }
            foreach (App::suggestions()->pendingByIds($clientId, $suggestionIds) as $s) {
                if (!isset($lines[(string) $s['value']])) {
                    $added[] = (string) $s['value'];
                }
            }
            $scope = ($lines !== [] ? '# ' . __('Current scope') . "\n" . implode("\n", array_keys($lines)) . "\n" : '')
                . ($added !== [] ? '# ' . __('Added from discovery') . "\n" . implode("\n", $added) . "\n" : '');
        }
        return $this->page('authorisations/form', __('Record scan authorisation'), [
            'client' => $client,
            'values' => [
                'approved_by_name' => '', 'approved_by_role' => '', 'approved_on' => $today,
                'valid_from' => $today, 'valid_until' => (new DateTimeImmutable($today))->modify('+1 year')->format('Y-m-d'),
                'document_ref' => '', 'notes' => '', 'scope' => $scope, 'confirm' => '',
                'replaces' => implode(',', $replaces),
            ],
            'added' => $added,
            'errors' => [],
            'scopeErrors' => [],
        ]);
    }

    /** POST /clients/{id}/authorisations */
    public function store(Request $request, array $params): Response
    {
        $client = $this->clientOr404($params);
        $clientId = (int) $client['id'];
        if ((int) $client['is_archived'] === 1) {
            Session::flash('danger', __('Restore the client before recording a new authorisation.'));
            return Response::redirect('/clients/' . $clientId);
        }
        $today = ScopeService::today((string) $client['timezone']);
        $values = [];
        foreach (['approved_by_name', 'approved_by_role', 'approved_on', 'valid_from', 'valid_until', 'document_ref', 'notes', 'confirm'] as $field) {
            $values[$field] = $request->input($field);
        }
        $values['scope'] = $request->raw('scope');
        $values['replaces'] = $request->input('replaces');
        $errors = [];
        // Authorisations this one replaces: only active or scheduled ones of THIS client are
        // revoked. Expired ones are left as they are, so the register's history stays true.
        $replaceIds = [];
        $revokedMeanwhile = [];
        if ($values['replaces'] !== '') {
            foreach (array_slice(explode(',', $values['replaces']), 0, 100) as $raw) {
                $auth = ctype_digit($raw) ? App::authorisations()->find((int) $raw) : null;
                if ($auth === null || (int) $auth['client_id'] !== $clientId) {
                    throw new HttpException(400, __('The authorisations to replace do not belong to this client.'));
                }
                $status = ScopeService::status($auth, $today);
                if ($status === ScopeService::STATUS_REVOKED) {
                    $revokedMeanwhile[] = (int) $auth['id'];
                } elseif ($status !== ScopeService::STATUS_EXPIRED) {
                    $replaceIds[] = (int) $auth['id'];
                }
            }
            $replaceIds = array_values(array_unique($replaceIds));
            if ($revokedMeanwhile !== []) {
                // Someone revoked it after this form was opened, perhaps for a reason. Don't quietly re-authorise its scope.
                $errors['scope'] = __('Authorisation #{ids} was revoked after you opened this form. Check that its targets should still be in the scope below, then save again.', ['ids' => implode(', #', $revokedMeanwhile)]);
                $values['replaces'] = implode(',', $replaceIds);
            }
        }

        foreach (['approved_by_name' => __('Enter the name of the person at the client who approved scanning.'),
                  'approved_by_role' => __('Enter their role, e.g. Managing Director or IT Manager.')] as $field => $message) {
            if ($values[$field] === '' || mb_strlen($values[$field]) > 150 || preg_match('/[\x00-\x1F\x7F]/u', $values[$field])) {
                $errors[$field] = $message;
            }
        }
        foreach (['approved_on', 'valid_from', 'valid_until'] as $field) {
            if (!self::isDate($values[$field])) {
                $errors[$field] = __('Enter a date (YYYY-MM-DD).');
            }
        }
        if (!isset($errors['approved_on']) && $values['approved_on'] > $today) {
            $errors['approved_on'] = __('The approval date cannot be in the future.');
        }
        // Both dates must be valid before comparing them.
        if (!isset($errors['valid_from']) && !isset($errors['valid_until'])) {
            if ($values['valid_until'] < $values['valid_from']) {
                $errors['valid_until'] = __('The end date must be on or after the start date.');
            } elseif ($values['valid_until'] > (new DateTimeImmutable($values['valid_from']))->modify('+2 years')->format('Y-m-d')) {
                $errors['valid_until'] = __('An authorisation can be valid for at most 2 years. Ask the client to renew it after that.');
            } elseif ($values['valid_until'] < $today) {
                $errors['valid_until'] = __('The end date is in the past.');
            }
        }
        if (mb_strlen($values['document_ref']) > 190) {
            $errors['document_ref'] = __('At most 190 characters.');
        }
        if (mb_strlen($values['notes']) > 2000) {
            $errors['notes'] = __('Notes can be at most 2000 characters.');
        }
        if ($replaceIds !== [] && !isset($errors['valid_from']) && $values['valid_from'] > $today) {
            // Revoking the current authorisation now would leave the client without scope until the new one starts.
            $errors['valid_from'] = __('A replacement must start today or earlier, otherwise the client has no active scope until it starts. To prepare a future renewal, record it without replacing and let the old one expire.');
        }
        if ($values['confirm'] !== '1') {
            $errors['confirm'] = __('Confirm that the client has given this authorisation.');
        }
        $parsed = App::scopeParser()->parseLines(mb_substr($values['scope'], 0, 100000));

        if ($errors !== [] || $parsed['errors'] !== []) {
            $scopeErrors = isset($errors['scope']) ? array_merge([$errors['scope']], $parsed['errors']) : $parsed['errors'];
            return $this->page('authorisations/form', __('Record scan authorisation'), [
                'client' => $client, 'values' => $values, 'errors' => $errors, 'scopeErrors' => $scopeErrors, 'added' => [],
            ], 422);
        }

        $clean = [
            'approved_by_name' => $values['approved_by_name'], 'approved_by_role' => $values['approved_by_role'],
            'approved_on' => $values['approved_on'], 'valid_from' => $values['valid_from'], 'valid_until' => $values['valid_until'],
            'document_ref' => $values['document_ref'], 'notes' => $values['notes'],
        ];
        $overlaps = App::authorisations()->overlapsWithOtherClients($clientId, $parsed['entries']);
        $id = App::authorisations()->create($clientId, $clean, $parsed['entries'], (int) $this->user()['id'], $replaceIds);
        App::suggestions()->markAccepted($clientId, array_map(static fn (array $e): array => [
            'entry_type' => $e['type'], 'value' => $e['value'], 'range_start' => $e['range']?->start, 'range_end' => $e['range']?->end,
        ], $parsed['entries']), (int) $this->user()['id']);
        foreach ($replaceIds as $replaced) {
            $this->audit($request, 'authorisation.revoked', 'authorisation', $replaced, ['client_id' => $clientId, 'reason' => 'Replaced by authorisation #' . $id]);
        }
        $this->audit($request, 'authorisation.created', 'authorisation', $id, [
            'client_id' => $clientId,
            'approved_by' => $clean['approved_by_name'] . ' (' . $clean['approved_by_role'] . ')',
            'valid' => $clean['valid_from'] . ' to ' . $clean['valid_until'],
            'scope' => array_map(static fn (array $e): string => $e['value'], $parsed['entries']),
            'confirmed_by_admin' => true,
            'replaces' => $replaceIds,
        ]);

        Session::flash('success', $replaceIds === []
            ? __('Authorisation recorded with {n} scope entries.', ['n' => count($parsed['entries'])])
            : __('Authorisation recorded with {n} scope entries. It replaces authorisation(s) #{ids}, which are now revoked.', ['n' => count($parsed['entries']), 'ids' => implode(', #', $replaceIds)]));
        foreach (array_slice($overlaps, 0, 10) as $hit) {
            Session::flash('warning', __('{value} is also in scope for client "{client}". Check that this is not a typo.', $hit));
        }
        return Response::redirect('/clients/' . $clientId);
    }

    /** POST /authorisations/{id}/revoke */
    public function revoke(Request $request, array $params): Response
    {
        $auth = App::authorisations()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
        $clientId = (int) $auth['client_id'];
        $reason = $request->input('reason');
        if ($reason === '' || mb_strlen($reason) > 500) {
            Session::flash('danger', __('Give a reason for revoking (up to 500 characters).'));
            return Response::redirect('/clients/' . $clientId);
        }
        if (!App::authorisations()->revoke((int) $auth['id'], (int) $this->user()['id'], $reason)) {
            Session::flash('info', __('This authorisation was already revoked.'));
            return Response::redirect('/clients/' . $clientId);
        }
        $this->audit($request, 'authorisation.revoked', 'authorisation', (int) $auth['id'], ['client_id' => $clientId, 'reason' => $reason]);
        Session::flash('success', __('Authorisation revoked. Its targets will no longer be scanned unless another active authorisation covers them.'));
        return Response::redirect('/clients/' . $clientId);
    }

    /** Strict YYYY-MM-DD check (rejects 2026-02-30). */
    private static function isDate(string $value): bool
    {
        if (!preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $value, $m)) {
            return false;
        }
        return checkdate((int) $m[2], (int) $m[3], (int) $m[1]) && (int) $m[1] >= 2000 && (int) $m[1] <= 2100;
    }

    /** @return array<string,mixed> The client, or a 404. */
    private function clientOr404(array $params): array
    {
        return App::clients()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
    }
}

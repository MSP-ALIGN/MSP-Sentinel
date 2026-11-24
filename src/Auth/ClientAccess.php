<?php

declare(strict_types=1);

namespace Sentinel\Auth;

/**
 * Which clients a user sees (1.41): every client, or a list. One place for the rule, used by the request kernel (a
 * client's pages and records), by the lists (dashboard, search, findings, reports, engagements) and by alerts.
 *
 * A user's client list is null for "every client" (users.all_clients = 1) or a list of client IDs. A user limited to a
 * list sees nothing of other clients: their pages and records answer 404 (as if they didn't exist), and lists, counts,
 * search, notifications and emails leave them out.
 *
 * Security assumptions: client IDs are integers from the database (cast here again); the SQL fragments contain only
 * integers and a column name from code, never input.
 */
final class ClientAccess
{
    /** Kinds of record a route can be addressed by, and how to find the record's client. Table and column are fixed. */
    public const RECORDS = [
        'finding' => ['findings', 'client_id'],
        'report' => ['reports', 'client_id'],
        'engagement' => ['engagements', 'client_id'],
        'scan' => ['scan_jobs', 'client_id'],
        'suggestion' => ['target_suggestions', 'client_id'],
        'authorisation' => ['scan_authorisations', 'client_id'],
        'site' => ['sites', 'client_id'],
    ];

    /**
     * True when the client list allows a client.
     *
     * @param list<int>|null $clientIds null: every client
     */
    public static function allows(?array $clientIds, int $clientId): bool
    {
        return $clientIds === null || in_array($clientId, $clientIds, true);
    }

    /**
     * An SQL condition (with a leading AND) limiting $column to the client list: '' for every client, an always-false
     * condition for an empty list. $column is a fixed column name from code (e.g. 'f.client_id').
     *
     * @param list<int>|null $clientIds
     */
    public static function sql(string $column, ?array $clientIds): string
    {
        if ($clientIds === null) {
            return '';
        }
        if (preg_match('/^[a-z_]+(\.[a-z_]+)?$/', $column) !== 1) {
            throw new \InvalidArgumentException('Bad column for a client filter');
        }
        $ids = array_values(array_unique(array_map('intval', $clientIds)));
        return $ids === [] ? ' AND 1 = 0' : ' AND ' . $column . ' IN (' . implode(',', $ids) . ')';
    }

    /**
     * True when list $inner is within list $outer (null = every client): a user can only give clients they see.
     *
     * @param list<int>|null $inner
     * @param list<int>|null $outer
     */
    public static function within(?array $inner, ?array $outer): bool
    {
        if ($outer === null) {
            return true;
        }
        return $inner !== null && array_diff($inner, $outer) === [];
    }
}

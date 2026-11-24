<?php

declare(strict_types=1);

namespace Sentinel\Search;

use PDO;

/**
 * The top bar's search (1.34): one query across clients, findings (title, target, CVE), external hosts (address,
 * names), internal devices (name, DNS name, addresses), engagements and help topics. Every signed-in user can see all
 * of these anyway (roles limit actions, not visibility), so results need no per-row checks; breach findings are
 * matched and shown by their masked title and target only (the full address stays in the finding's details).
 *
 * Untrusted: the query text. It is trimmed, limited to 100 characters, and used only as a bound LIKE parameter with
 * the LIKE wildcards (% and _) and the escape character escaped, so it matches literally. Each group is capped.
 */
final class SearchService
{
    public const MIN_LENGTH = 2;
    public const MAX_LENGTH = 100;
    private const PER_GROUP = 25;

    public function __construct(private readonly PDO $db)
    {
    }

    /** The query as used: trimmed, single-spaced, at most MAX_LENGTH characters; '' when too short. */
    public static function normalise(string $q): string
    {
        $q = mb_substr(trim((string) preg_replace('/\s+/u', ' ', $q)), 0, self::MAX_LENGTH);
        return mb_strlen($q) >= self::MIN_LENGTH ? $q : '';
    }

    /** A LIKE pattern matching $q anywhere, literally (wildcards escaped with "!"). */
    public static function like(string $q): string
    {
        return '%' . strtr($q, ['!' => '!!', '%' => '!%', '_' => '!_']) . '%';
    }

    /**
     * @param list<array{title:string, paragraphs:list<string>}> $helpTopics
     * @return array{clients:list<array<string,mixed>>, findings:list<array<string,mixed>>, hosts:list<array<string,mixed>>,
     *               devices:list<array<string,mixed>>, engagements:list<array<string,mixed>>, help:list<array{title:string, snippet:string}>, total:int}
     */
    public function search(string $q, array $helpTopics = [], ?array $clientIds = null): array
    {
        // Only the signed-in user's clients (1.41; null: every client). Fixed column names, integer IDs.
        $only = static fn (string $col): string => \Sentinel\Auth\ClientAccess::sql($col, $clientIds);
        $q = self::normalise($q);
        $out = ['clients' => [], 'findings' => [], 'hosts' => [], 'devices' => [], 'engagements' => [], 'help' => [], 'total' => 0];
        if ($q === '') {
            return $out;
        }
        $p = self::like($q);
        $n = self::PER_GROUP;
        $out['clients'] = $this->rows("SELECT id, name, is_archived FROM clients WHERE name LIKE :p ESCAPE '!'" . $only('id') . " ORDER BY is_archived, name LIMIT {$n}", ['p' => $p]);
        // Breach findings carry the full address only in the detail, which isn't searched.
        $out['findings'] = $this->rows(
            "SELECT f.id, f.title, f.target, f.severity, f.status, f.finding_type, c.name AS client_name FROM findings f JOIN clients c ON c.id = f.client_id
             WHERE c.is_archived = 0 AND (f.title LIKE :p1 ESCAPE '!' OR f.target LIKE :p2 ESCAPE '!' OR f.cve_id LIKE :p3 ESCAPE '!')" . $only('f.client_id') . "
             ORDER BY f.status = 'open' DESC, f.severity = 'fail' DESC, f.last_seen DESC LIMIT {$n}", ['p1' => $p, 'p2' => $p, 'p3' => $p]);
        $out['hosts'] = $this->rows(
            "SELECT a.id, a.ip, a.hostnames, a.client_id, c.name AS client_name FROM assets a JOIN clients c ON c.id = a.client_id
             WHERE c.is_archived = 0 AND (a.ip LIKE :p1 ESCAPE '!' OR a.hostnames LIKE :p2 ESCAPE '!')" . $only('a.client_id') . " ORDER BY c.name, a.ip LIMIT {$n}", ['p1' => $p, 'p2' => $p]);
        $out['devices'] = $this->rows(
            "SELECT d.id, d.name, d.dns_name, d.ip_addresses, d.client_id, c.name AS client_name FROM devices d JOIN clients c ON c.id = d.client_id
             WHERE c.is_archived = 0 AND (d.name LIKE :p1 ESCAPE '!' OR d.dns_name LIKE :p2 ESCAPE '!' OR d.ip_addresses LIKE :p3 ESCAPE '!')" . $only('d.client_id') . "
             ORDER BY c.name, d.name LIMIT {$n}", ['p1' => $p, 'p2' => $p, 'p3' => $p]);
        $out['engagements'] = $this->rows(
            "SELECT e.id, e.name, e.window_start, e.client_id, c.name AS client_name FROM engagements e JOIN clients c ON c.id = e.client_id
             WHERE e.name LIKE :p ESCAPE '!'" . $only('e.client_id') . " ORDER BY e.id DESC LIMIT {$n}", ['p' => $p]);
        $needle = mb_strtolower($q);
        foreach ($helpTopics as $t) {
            $text = $t['title'] . ' ' . implode(' ', $t['paragraphs']);
            $pos = mb_strpos(mb_strtolower($text), $needle);
            if ($pos !== false && count($out['help']) < 10) {
                $start = max(0, $pos - 60);
                $out['help'][] = ['title' => $t['title'], 'snippet' => ($start > 0 ? '…' : '') . mb_substr($text, $start, 180) . '…'];
            }
        }
        $out['total'] = count($out['clients']) + count($out['findings']) + count($out['hosts']) + count($out['devices']) + count($out['engagements']) + count($out['help']);
        return $out;
    }

    /**
     * @param array<string,string> $params
     * @return list<array<string,mixed>>
     */
    private function rows(string $sql, array $params): array
    {
        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }
}

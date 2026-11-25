<?php

declare(strict_types=1);

/**
 * Migration 0058 (1.50; reworked in 1.50.1): certificate expiry findings get one key per certificate
 * ("...:cert_validity") for both "expires soon" and "expired", so the finding escalates instead of being replaced on
 * the day. Existing findings are moved to the new key, title and evidence form (the evidence starts with the key code,
 * and a changed evidence would reopen decided findings).
 *
 * Where both old keys exist for one certificate endpoint, the finding that matters most keeps the new key: an open
 * one, then accepted, then false positive, then resolved; among equals the one seen last. An open finding that loses
 * is resolved with the reason 'merged', so its ticket gets an honest note instead of "Verified fixed".
 *
 * Input is the findings table only (finding keys built by Sentinel from scan results: treated as data, all values
 * bound). Idempotent: only keys still ending in the old codes are read, and an endpoint whose new key already exists
 * is not renamed again (its leftover open old-key findings are merged as above).
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'One finding key for certificate expiry',
    'up' => static function (PDO $db, Migrator $m): void {
        $titles = ['cert_expired' => 'Certificate expired', 'cert_expiring' => 'Certificate expires soon'];
        $rank = ['open' => 0, 'accepted' => 1, 'false_positive' => 2];
        $rows = $db->query("SELECT id, client_id, finding_key, status, last_seen FROM findings
                            WHERE finding_type = 'tls' AND (finding_key LIKE 'tls:%:cert\\_expired' OR finding_key LIKE 'tls:%:cert\\_expiring')")->fetchAll();
        $groups = [];
        foreach ($rows as $r) {
            $code = str_ends_with($r['finding_key'], ':cert_expired') ? 'cert_expired' : 'cert_expiring';
            $new = substr($r['finding_key'], 0, -strlen($code)) . 'cert_validity';
            $r['code'] = $code;
            $groups[$r['client_id'] . "\n" . $new][] = $r;
        }
        $exists = $db->prepare('SELECT COUNT(*) FROM findings WHERE client_id = :c AND finding_key = :k');
        $rename = $db->prepare("UPDATE IGNORE findings SET finding_key = :k, title = :t,
                                       evidence = IF(LOCATE('|', evidence) > 0, CONCAT('cert_validity', SUBSTRING(evidence, LOCATE('|', evidence))), evidence)
                                WHERE id = :id");
        $merge = $db->prepare("UPDATE findings SET resolved_from = status, status = 'resolved', resolved_at = UTC_TIMESTAMP(), updated_at = UTC_TIMESTAMP(),
                                      resolved_reason = 'merged' WHERE id = :id AND status = 'open'");
        foreach ($groups as $key => $list) {
            [$clientId, $new] = explode("\n", $key, 2);
            usort($list, static fn (array $a, array $b): int => [$rank[$a['status']] ?? 3, (string) $b['last_seen']] <=> [$rank[$b['status']] ?? 3, (string) $a['last_seen']]);
            $exists->execute(['c' => (int) $clientId, 'k' => $new]);
            $start = 0;
            if ((int) $exists->fetchColumn() === 0) {
                $w = $list[0];
                $rename->execute(['k' => $new, 't' => $titles[$w['code']], 'id' => (int) $w['id']]);
                $start = 1;
            }
            // The rest stay on their old key (history); open ones close as merged, not as fixed.
            foreach (array_slice($list, $start) as $loser) {
                $merge->execute(['id' => (int) $loser['id']]);
            }
        }
    },
];

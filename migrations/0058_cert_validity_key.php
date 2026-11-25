<?php

declare(strict_types=1);

/**
 * Migration 0058 (1.50): certificate expiry findings get one key per certificate ("...:cert_validity") for both
 * "expires soon" and "expired", so the finding escalates instead of being replaced on the day. Existing keys are
 * renamed (an expired one first, so it wins where both exist; the other stays as it is and resolves). Titles lose
 * their day count. Ticket rows point at findings by ID and are unaffected.
 *
 * Idempotent: only keys still ending in the old codes are changed; UPDATE IGNORE skips a key that already exists.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'One finding key for certificate expiry',
    'up' => static function (PDO $db, Migrator $m): void {
        foreach (['cert_expired' => 'Certificate expired', 'cert_expiring' => 'Certificate expires soon'] as $code => $title) {
            $stmt = $db->prepare("UPDATE IGNORE findings SET finding_key = CONCAT(LEFT(finding_key, CHAR_LENGTH(finding_key) - :len), 'cert_validity'), title = :t
                                  WHERE finding_type = 'tls' AND finding_key LIKE CONCAT('tls:%:', :code)");
            $stmt->execute(['len' => strlen($code), 't' => $title, 'code' => $code]);
        }
    },
];

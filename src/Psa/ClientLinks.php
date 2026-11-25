<?php

declare(strict_types=1);

namespace Sentinel\Psa;

use PDO;

/**
 * Links between Sentinel clients and their clients in a ticketing system (psa_client_links, 1.54). Every change to a
 * link goes through set(), which also keeps the compatibility column clients.itflow_client_id in step for ITFlow (the
 * REST API and MSP Align matching read it).
 *
 * Untrusted: the external ID (from an admin's form or the PSA's client list). It is stored as text, at most 64
 * characters, compared exactly; callers check its form first (e.g. ITFlow IDs are whole numbers). The provider name
 * comes from code. A PSA client can be linked to one Sentinel client only (unique key; set() refuses otherwise).
 */
final class ClientLinks
{
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Link a client to a PSA client, or unlink it (null). Refuses (DomainException) when that PSA client is linked to
     * another Sentinel client or the ID isn't valid; a link made elsewhere at the same moment fails with PDOException 1062.
     */
    public function set(int $clientId, string $provider, ?string $externalId): void
    {
        if ($externalId !== null && ($externalId === '' || strlen($externalId) > 64
            || ($provider === 'itflow' && preg_match('/^[1-9][0-9]{0,9}$/', $externalId) !== 1))) { // ITFlow: whole numbers, written plainly (1.54.1)
            throw new \DomainException('Not a valid client ID for ' . $provider . '.');
        }
        $owner = $externalId === null ? null : $this->clientFor($provider, $externalId);
        if ($owner !== null && $owner !== $clientId) {
            throw new \DomainException('That client in ' . $provider . ' is already linked to another Sentinel client.');
        }
        if ($externalId === null) {
            $this->db->prepare('DELETE FROM psa_client_links WHERE client_id = :c AND provider = :p')->execute(['c' => $clientId, 'p' => $provider]);
        } elseif ($this->externalFor($clientId, $provider) !== null) {
            // Update, then insert, never "insert or update" (1.54.1): a PSA client someone linked elsewhere in the meantime
            // then fails on the unique key (PDOException 1062) instead of being silently skipped.
            $this->db->prepare('UPDATE psa_client_links SET linked_at = IF(external_id = :e1, linked_at, UTC_TIMESTAMP()), external_id = :e2 WHERE client_id = :c AND provider = :p')
                ->execute(['e1' => $externalId, 'e2' => $externalId, 'c' => $clientId, 'p' => $provider]);
        } else {
            $this->db->prepare('INSERT INTO psa_client_links (client_id, provider, external_id, linked_at) VALUES (:c, :p, :e, UTC_TIMESTAMP())')
                ->execute(['c' => $clientId, 'p' => $provider, 'e' => $externalId]);
        }
        if ($provider === 'itflow') {
            // The compatibility column: ITFlow IDs are whole numbers (anything else is never stored there).
            $int = $externalId !== null && ctype_digit($externalId) ? (int) $externalId : null;
            $this->db->prepare('UPDATE clients SET itflow_client_id = :i WHERE id = :c AND NOT (itflow_client_id <=> :i2)')->execute(['i' => $int, 'i2' => $int, 'c' => $clientId]);
        }
    }

    /** The Sentinel client linked to a PSA client, or null. */
    public function clientFor(string $provider, string $externalId): ?int
    {
        $stmt = $this->db->prepare('SELECT client_id FROM psa_client_links WHERE provider = :p AND external_id = :e');
        $stmt->execute(['p' => $provider, 'e' => $externalId]);
        $id = $stmt->fetchColumn();
        return $id === false ? null : (int) $id;
    }

    /** A client's ID in a PSA, or null when it isn't linked there. */
    public function externalFor(int $clientId, string $provider): ?string
    {
        $stmt = $this->db->prepare('SELECT external_id FROM psa_client_links WHERE client_id = :c AND provider = :p');
        $stmt->execute(['c' => $clientId, 'p' => $provider]);
        $id = $stmt->fetchColumn();
        return $id === false ? null : (string) $id;
    }
}

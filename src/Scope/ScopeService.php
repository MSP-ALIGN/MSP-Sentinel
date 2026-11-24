<?php

declare(strict_types=1);

namespace Sentinel\Scope;

use DateTimeImmutable;
use DateTimeZone;
use Sentinel\Clients\ClientRepository;
use Sentinel\Core\Settings;

/**
 * Answers "may Sentinel scan this target for this client right now?". This is
 * the ONE place later steps (scheduler, worker) must ask before anything
 * touches a host.
 *
 * A target is in scope only if ALL of these hold:
 * 1. Scanning isn't paused globally (kill switch).
 * 2. The client exists, isn't archived and isn't paused.
 * 3. A not-revoked authorisation of that client is valid today (in the
 *    client's timezone).
 * 4. The target matches one of that authorisation's scope entries: the IP
 *    lies inside an IP/CIDR entry, or the hostname equals a domain entry,
 *    or is a subdomain of a "*." entry.
 *
 * Security assumptions:
 * - It fails closed: unknown clients, bad timezones, non-canonical or
 *   malformed targets and database surprises all mean "not in scope".
 * - It re-reads the client row and the global switch on every call, so
 *   pauses apply immediately.
 * - A hostname match is NOT enough to scan the addresses it resolves to.
 *   The worker (a later step) must also check each resolved IP, because a
 *   client's DNS record could point at a third party's server.
 */
final class ScopeService
{
    public const STATUS_ACTIVE = 'active';
    public const STATUS_SCHEDULED = 'scheduled';
    public const STATUS_EXPIRED = 'expired';
    public const STATUS_REVOKED = 'revoked';

    /** Needs the authorisation and client stores, and the settings (for the global kill switch). */
    public function __construct(
        private readonly AuthorisationRepository $authorisations,
        private readonly Settings $settings,
        private readonly ClientRepository $clients,
    )
    {
    }

    /** True when the global kill switch is on. */
    public function globallyPaused(): bool
    {
        // Read fresh every time: a pause must take effect immediately, even in a long-running worker.
        return $this->settings->fresh('scanning_paused') === '1';
    }

    /**
     * Today's date in a client's timezone (falls back to UTC for an invalid zone).
     */
    public static function today(string $timezone, ?DateTimeImmutable $now = null): string
    {
        try {
            $zone = new DateTimeZone($timezone);
        } catch (\Exception) {
            $zone = new DateTimeZone('UTC');
        }
        return ($now ?? new DateTimeImmutable('now'))->setTimezone($zone)->format('Y-m-d');
    }

    /**
     * Status of one authorisation on a given day.
     *
     * @param array<string,mixed> $authorisation Row from scan_authorisations.
     * @param string              $today         Y-m-d in the client's timezone.
     */
    public static function status(array $authorisation, string $today): string
    {
        if ($authorisation['revoked_at'] !== null) {
            return self::STATUS_REVOKED;
        }
        if ($today < (string) $authorisation['valid_from']) {
            return self::STATUS_SCHEDULED;
        }
        if ($today > (string) $authorisation['valid_until']) {
            return self::STATUS_EXPIRED;
        }
        return self::STATUS_ACTIVE;
    }

    /**
     * May this target be scanned for this client now?
     *
     * The client row is re-read from the database on every call, and so is the
     * global kill switch, so a pause or archive takes effect at once, even
     * for a long-running worker.
     *
     * The target must already be in canonical form (see canonicalTarget()):
     * a lower-case hostname without a trailing dot, or an IP exactly as
     * inet_ntop() writes it. Anything else is refused rather than cleaned
     * up, so the caller can't check one string and then scan another.
     *
     * @param string $target Untrusted: an IP address or a hostname.
     */
    public function isInScope(int $clientId, string $target, ?DateTimeImmutable $now = null): bool
    {
        try {
            if ($this->globallyPaused() || self::canonicalTarget($target) !== $target) {
                return false;
            }
            $client = $this->clients->find($clientId);
            if ($client === null || (int) $client['is_archived'] === 1 || (int) $client['scanning_paused'] === 1) {
                return false;
            }
            if (!in_array((string) $client['timezone'], \DateTimeZone::listIdentifiers(), true)) {
                return false; // an invalid timezone means we can't tell which day it is there: fail closed
            }
            $entries = $this->authorisations->activeEntries($clientId, self::today((string) $client['timezone'], $now));
            if ($entries === []) {
                return false;
            }
            return self::matches($entries, $target);
        } catch (\Throwable $ex) {
            error_log('[msp-sentinel] scope check failed closed: ' . $ex->getMessage());
            return false;
        }
    }

    /**
     * Does a canonical target match any of these scope entries? Pure function,
     * no kill switch or date checks (isInScope() does those). Also used by
     * discovery to tell new names from ones already in scope.
     *
     * @param list<array{entry_type:string,value:string,range_start:?string,range_end:?string}> $entries
     */
    public static function matches(array $entries, string $target): bool
    {
        if (filter_var($target, FILTER_VALIDATE_IP) !== false) {
            $ip = IpRange::parse($target);
            if ($ip === null) {
                return false;
            }
            foreach ($entries as $e) {
                if ($e['range_start'] !== null && strlen((string) $e['range_start']) === strlen($ip->start)
                    && strcmp($ip->start, (string) $e['range_start']) >= 0 && strcmp($ip->start, (string) $e['range_end']) <= 0) {
                    return true;
                }
            }
            return false;
        }
        foreach ($entries as $e) {
            if ($e['entry_type'] !== 'domain') {
                continue;
            }
            $value = (string) $e['value'];
            if ($value === $target) {
                return true;
            }
            // "*.client.example" covers "www.client.example" and "a.b.client.example", but not "client.example" itself.
            if (str_starts_with($value, '*.') && str_ends_with($target, substr($value, 1))) {
                return true;
            }
        }
        return false;
    }

    /**
     * The canonical form of a target, or null if it isn't a valid IP or hostname.
     * Callers convert ONCE, then use only the returned string, both for
     * isInScope() and for the scan itself.
     *
     * @param string $target Untrusted.
     */
    public static function canonicalTarget(string $target): ?string
    {
        if (filter_var($target, FILTER_VALIDATE_IP) !== false) {
            $packed = inet_pton($target);
            return $packed === false ? null : (string) inet_ntop($packed);
        }
        $host = strtolower($target);
        // Same label rules as ScopeParser: letters, digits and inner hyphens, at least two labels.
        if (!preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$/D', $host)) {
            return null;
        }
        return $host;
    }
}

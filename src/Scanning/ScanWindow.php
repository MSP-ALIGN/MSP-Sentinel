<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

use DateTimeImmutable;
use DateTimeZone;

/**
 * Is it currently inside a client's scan window (in the client's timezone)?
 *
 * Windows may cross midnight: 22:00 to 06:00 means "from 22:00 until 06:00
 * the next morning". The start time is inclusive and the end time exclusive.
 *
 * Security assumptions: fails closed. An invalid timezone or time means
 * "not in the window".
 */
final class ScanWindow
{
    /** @param array<string,mixed> $client Row with timezone, scan_window_start, scan_window_end ("HH:MM:SS"). */
    public static function isOpen(array $client, ?DateTimeImmutable $now = null): bool
    {
        try {
            $zone = new DateTimeZone((string) $client['timezone']);
        } catch (\Exception) {
            return false;
        }
        $start = substr((string) $client['scan_window_start'], 0, 5);
        $end = substr((string) $client['scan_window_end'], 0, 5);
        if (!preg_match('/^\d\d:\d\d$/', $start) || !preg_match('/^\d\d:\d\d$/', $end) || $start === $end) {
            return false;
        }
        $local = ($now ?? new DateTimeImmutable('now'))->setTimezone($zone)->format('H:i');
        return $start < $end
            ? ($local >= $start && $local < $end)
            : ($local >= $start || $local < $end); // crosses midnight
    }

    /**
     * When the window next opens or closes, as a UTC time, or null if the window is
     * invalid (fails closed: treated as never open).
     *
     * @param array<string,mixed> $client
     * @return array{open:bool, at:DateTimeImmutable}|null "open" is the state now; "at" is when it changes.
     */
    public static function nextChange(array $client, ?DateTimeImmutable $now = null): ?array
    {
        try {
            $zone = new DateTimeZone((string) $client['timezone']);
        } catch (\Exception) {
            return null;
        }
        $start = substr((string) $client['scan_window_start'], 0, 5);
        $end = substr((string) $client['scan_window_end'], 0, 5);
        if (!preg_match('/^\d\d:\d\d$/', $start) || !preg_match('/^\d\d:\d\d$/', $end) || $start === $end) {
            return null;
        }
        $local = ($now ?? new DateTimeImmutable('now'))->setTimezone($zone);
        $open = self::isOpen($client, $local);
        $target = $open ? $end : $start;
        $at = $local->setTime((int) substr($target, 0, 2), (int) substr($target, 3, 2));
        if ($at <= $local) {
            $at = $at->modify('+1 day');
        }
        return ['open' => $open, 'at' => $at->setTimezone(new DateTimeZone('UTC'))];
    }
}

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
}

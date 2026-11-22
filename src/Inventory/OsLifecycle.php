<?php

declare(strict_types=1);

namespace Sentinel\Inventory;

/**
 * End of security updates for Windows versions, by build number and edition,
 * from Microsoft's published lifecycle dates. Used to flag devices that no
 * longer get security fixes.
 *
 * Only versions listed here are judged; anything else (macOS, Linux, unknown
 * builds) gets no verdict. Extended Security Updates (paid ESU) can't be
 * seen from inventory data: the finding says so, and an enrolled device can
 * be marked as an accepted risk. Update this table when Microsoft publishes
 * new dates (each release lists it in the changelog).
 *
 * Untrusted: OS names and builds come from the inventory source and are
 * only matched with fixed patterns.
 */
final class OsLifecycle
{
    /** Windows 10 Home/Pro, by build. */
    private const WIN10 = [10240 => '2017-05-09', 10586 => '2017-10-10', 14393 => '2018-04-10', 15063 => '2018-10-09', 16299 => '2019-04-09',
        17134 => '2019-11-12', 17763 => '2020-11-10', 18362 => '2020-12-08', 18363 => '2021-05-11', 19041 => '2021-12-14', 19042 => '2022-05-10',
        19043 => '2022-12-13', 19044 => '2023-06-13', 19045 => '2025-10-14'];
    /** Windows 10 Enterprise/Education (longer for some versions). */
    private const WIN10_ENTERPRISE = [10240 => '2017-05-09', 10586 => '2017-10-10', 14393 => '2019-04-09', 15063 => '2019-10-08', 16299 => '2020-10-13',
        17134 => '2021-05-11', 17763 => '2021-05-11', 18362 => '2020-12-08', 18363 => '2022-05-10', 19041 => '2021-12-14', 19042 => '2023-05-09',
        19043 => '2022-12-13', 19044 => '2024-06-11', 19045 => '2025-10-14'];
    /** Windows 10 Enterprise LTSB/LTSC. */
    private const WIN10_LTSC = [10240 => '2025-10-14', 14393 => '2026-10-13', 17763 => '2029-01-09', 19044 => '2027-01-12'];
    /** Windows 11 Home/Pro. */
    private const WIN11 = [22000 => '2023-10-10', 22621 => '2024-10-08', 22631 => '2025-11-11', 26100 => '2026-10-13', 26200 => '2027-10-12'];
    /** Windows 11 Enterprise/Education. */
    private const WIN11_ENTERPRISE = [22000 => '2024-10-08', 22621 => '2025-10-14', 22631 => '2026-11-10', 26100 => '2027-10-12', 26200 => '2028-10-10'];
    /** Windows Server, by build. */
    private const SERVER = [6001 => '2020-01-14', 6002 => '2020-01-14', 7600 => '2020-01-14', 7601 => '2020-01-14', 9200 => '2023-10-10', 9600 => '2023-10-10',
        14393 => '2027-01-12', 17763 => '2029-01-09', 20348 => '2031-10-14'];
    /** Older Windows client versions. */
    private const LEGACY = [6001 => '2017-04-11', 6002 => '2017-04-11', 7600 => '2020-01-14', 7601 => '2020-01-14', 9200 => '2016-01-12', 9600 => '2023-01-10'];

    /**
     * When security updates end (Y-m-d) for this OS, or null when it isn't in the table.
     */
    public static function endOfSupport(string $osName, string $build): ?string
    {
        if (stripos($osName, 'windows') === false) {
            return null;
        }
        $b = self::build($build !== '' ? $build : $osName);
        if ($b === null) {
            return null;
        }
        $table = match (true) {
            stripos($osName, 'server') !== false => self::SERVER,
            $b < 10000 => self::LEGACY,
            preg_match('/\bLTS[BC]\b/i', $osName) === 1 => self::WIN10_LTSC,
            $b >= 22000 => preg_match('/\b(Enterprise|Education)\b/i', $osName) === 1 ? self::WIN11_ENTERPRISE : self::WIN11,
            default => preg_match('/\b(Enterprise|Education)\b/i', $osName) === 1 ? self::WIN10_ENTERPRISE : self::WIN10,
        };
        return $table[$b] ?? null;
    }

    /** The Windows build number ("19045", "10.0.19045", "10.0.19045.3803"), or null. */
    private static function build(string $text): ?int
    {
        if (preg_match('/\b(?:\d+\.\d+\.)?(\d{4,5})(?:\.\d+)?\b/', $text, $m) !== 1) {
            return null;
        }
        return (int) $m[1];
    }
}

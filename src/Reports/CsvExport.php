<?php

declare(strict_types=1);

namespace Sentinel\Reports;

/**
 * CSV export of a report's findings (from the frozen snapshot, so it matches the report).
 *
 * Security assumptions: cell values are scan data (untrusted). Values that a
 * spreadsheet would treat as a formula (starting with = + - @, tab, CR, LF, or
 * their fullwidth forms) are
 * prefixed with an apostrophe (CSV/formula injection). fputcsv quotes the rest.
 */
final class CsvExport
{
    public const COLUMNS = ['status', 'severity', 'type', 'title', 'target', 'host', 'detail', 'evidence', 'cve', 'known_exploited', 'epss',
                            'confidence', 'how_to_fix', 'first_seen', 'last_seen', 'resolved_at', 'triage_note'];

    /** @param array<string,mixed> $snapshot */
    public static function build(array $snapshot): string
    {
        if (in_array($snapshot['kind'] ?? '', ['pentest', 'retest'], true)) {
            return self::engagement($snapshot);
        }
        $out = fopen('php://temp', 'r+');
        fwrite($out, "\xEF\xBB\xBF"); // UTF-8 BOM so spreadsheet programs read accents correctly
        fputcsv($out, self::COLUMNS, ',', '"', '');
        foreach (array_merge($snapshot['open'], $snapshot['decided'], $snapshot['fixed']) as $f) {
            fputcsv($out, array_map([self::class, 'cell'], [
                $f['status'], $f['severity'], $f['finding_type'], $f['title'], $f['target'], $f['asset'] ?? '', $f['detail'], $f['evidence'],
                $f['cve_id'] ?? '', $f['finding_type'] === 'vuln' ? ((int) $f['in_kev'] === 1 ? 'yes' : 'no') : '', $f['epss'] ?? '',
                $f['confidence'] ?? '', $f['fix'] ?? '', $f['first_seen'], $f['last_seen'], $f['resolved_at'] ?? '', $f['triage_note'] ?? '',
            ]), ',', '"', '');
        }
        rewind($out);
        return (string) stream_get_contents($out);
    }

    /** A pen-test report's findings as CSV (severity, finding, where, inside or from the internet, evidence, fix). @param array<string,mixed> $snapshot */
    private static function engagement(array $snapshot): string
    {
        $out = fopen('php://temp', 'r+');
        fwrite($out, "\xEF\xBB\xBF");
        fputcsv($out, ['severity', 'finding', 'target', 'origin', 'evidence', 'how_to_fix'], ',', '"', '');
        foreach ((array) ($snapshot['findings'] ?? []) as $f) {
            fputcsv($out, array_map([self::class, 'cell'], [$f['severity'] ?? '', $f['title'] ?? '', $f['target'] ?? '', $f['origin'] ?? '', $f['evidence'] ?? '', $f['fix'] ?? '']), ',', '"', '');
        }
        rewind($out);
        return (string) stream_get_contents($out);
    }

    /** Neutralise spreadsheet formulas. */
    public static function cell(mixed $value): string
    {
        $v = (string) ($value ?? '');
        $pattern = mb_check_encoding($v, 'UTF-8') ? '/^[=+\-@\t\r\n\x{FF1D}\x{FF0B}\x{FF0D}\x{FF20}]/u' : '/^[=+\-@\t\r\n]/';
        return preg_match($pattern, $v) === 1 ? "'" . $v : $v;
    }
}

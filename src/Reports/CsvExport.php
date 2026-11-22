<?php

declare(strict_types=1);

namespace Sentinel\Reports;

/**
 * CSV export of a report's findings (from the frozen snapshot, so it matches the report).
 *
 * Security assumptions: cell values are scan data (untrusted). Values that a
 * spreadsheet would treat as a formula (starting with = + - @, tab or CR) are
 * prefixed with an apostrophe (CSV/formula injection). fputcsv quotes the rest.
 */
final class CsvExport
{
    public const COLUMNS = ['status', 'severity', 'type', 'title', 'target', 'host', 'detail', 'evidence', 'cve', 'known_exploited', 'epss',
                            'confidence', 'how_to_fix', 'first_seen', 'last_seen', 'resolved_at', 'triage_note'];

    /** @param array<string,mixed> $snapshot */
    public static function build(array $snapshot): string
    {
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

    /** Neutralise spreadsheet formulas. */
    public static function cell(mixed $value): string
    {
        $v = (string) ($value ?? '');
        return preg_match('/^[=+\-@\t\r]/', $v) ? "'" . $v : $v;
    }
}

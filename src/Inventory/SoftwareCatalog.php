<?php

declare(strict_types=1);

namespace Sentinel\Inventory;

/**
 * Maps installed-program names (as Windows and macOS report them) to the
 * CPE product names NVD uses, so installed software can be matched to known
 * vulnerabilities.
 *
 * Honest by design: only programs in this list are matched, by an anchored
 * pattern on the whole name, and only with a clean version number (from the
 * version field, or from the name when the field is empty). Anything else is
 * shown as "not in the software catalogue", never guessed. Products whose
 * versions don't line up with NVD (Microsoft Office, Java "Update" numbers)
 * are left out on purpose.
 *
 * Untrusted: names, publishers and versions come from the inventory source.
 * They are only matched with fixed patterns.
 */
final class SoftwareCatalog
{
    /**
     * product label => [name pattern (no anchors), CPE 2.2 prefix (vendor:product)]. The whole program name must be
     * the product name followed only by SUFFIX parts (version numbers, "(x64)"-style brackets, x64/x86, a language
     * code), so "Google Chrome Helper" or "Microsoft Edge WebView2 Runtime" are never read as the browser.
     */
    public const PRODUCTS = [
        'Google Chrome' => ['Google Chrome', 'cpe:/a:google:chrome'],
        'Mozilla Firefox ESR' => ['Mozilla Firefox(?: \\d[\\d.]*)? ESR', 'cpe:/a:mozilla:firefox_esr'],
        'Mozilla Firefox' => ['Mozilla Firefox', 'cpe:/a:mozilla:firefox'],
        'Mozilla Thunderbird' => ['Mozilla Thunderbird', 'cpe:/a:mozilla:thunderbird'],
        'Microsoft Edge' => ['Microsoft Edge', 'cpe:/a:microsoft:edge_chromium'],
        '7-Zip' => ['7-Zip', 'cpe:/a:7-zip:7-zip'],
        'Notepad++' => ['Notepad\\+\\+', 'cpe:/a:notepad-plus-plus:notepad++'],
        'Adobe Acrobat Reader' => ['Adobe Acrobat Reader(?: DC)?', 'cpe:/a:adobe:acrobat_reader_dc'],
        'Adobe Acrobat' => ['Adobe Acrobat(?: DC)?', 'cpe:/a:adobe:acrobat_dc'],
        'VLC media player' => ['VLC media player', 'cpe:/a:videolan:vlc_media_player'],
        'PuTTY' => ['PuTTY(?: release)?', 'cpe:/a:putty:putty'],
        'WinSCP' => ['WinSCP', 'cpe:/a:winscp:winscp'],
        'WinRAR' => ['WinRAR', 'cpe:/a:rarlab:winrar'],
        'Wireshark' => ['Wireshark', 'cpe:/a:wireshark:wireshark'],
        'FileZilla Client' => ['FileZilla(?: Client)?', 'cpe:/a:filezilla-project:filezilla_client'],
        'TeamViewer' => ['TeamViewer', 'cpe:/a:teamviewer:teamviewer'],
        'AnyDesk' => ['AnyDesk', 'cpe:/a:anydesk:anydesk'],
        'KeePass' => ['KeePass(?: Password Safe)?', 'cpe:/a:keepass:keepass'],
        'Git' => ['Git(?: version)?', 'cpe:/a:git-scm:git'],
        'Node.js' => ['Node\\.js', 'cpe:/a:nodejs:node.js'],
        'Python' => ['Python \\d+\\.\\d+(?:\\.\\d+)?', 'cpe:/a:python:python'],
    ];

    /** What may follow a product name: versions, bracketed notes like "(x64 en-US)", x64/x86, a language code. */
    private const SUFFIX = '(?:\\s+(?:\\d[\\d.]*|\\([^)]{0,40}\\)|x64|x86|[a-z]{2}(?:-[a-z]{2})?))*';


    /**
     * Identify one installed program.
     *
     * @return array{product:string, cpe:string}|null cpe includes the version (CPE 2.2), or null if not in the catalogue
     *         or the version isn't a clean number.
     */
    public static function identify(string $name, string $version): ?array
    {
        $name = trim($name);
        if ($name === '' || strlen($name) > 255) {
            return null;
        }
        foreach (self::PRODUCTS as $label => [$pattern, $cpe]) {
            if (preg_match('/^' . $pattern . self::SUFFIX . '$/i', $name) !== 1) {
                continue;
            }
            $v = self::version($version !== '' ? $version : $name);
            return $v === null ? null : ['product' => $label, 'cpe' => $cpe . ':' . $v];
        }
        return null;
    }

    /** True if a program is in the catalogue at all (for "not in the catalogue" counts). */
    public static function known(string $name): bool
    {
        foreach (self::PRODUCTS as [$pattern]) {
            if (preg_match('/^' . $pattern . self::SUFFIX . '$/i', trim($name)) === 1) {
                return true;
            }
        }
        return false;
    }

    /** A clean dotted version number (e.g. "120.0.6099.130"), or null. */
    private static function version(string $text): ?string
    {
        return preg_match('/(?<![\d.])(\d{1,6}(?:\.\d{1,6}){1,4})(?![\d.])/', $text, $m) === 1 ? $m[1] : null;
    }
}

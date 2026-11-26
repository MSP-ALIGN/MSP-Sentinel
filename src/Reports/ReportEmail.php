<?php

declare(strict_types=1);

namespace Sentinel\Reports;

use Sentinel\Core\Settings;

/**
 * The branded HTML version of the report email (1.59): a header in the brand color with the logo, the message, and
 * the contact block, in a simple table layout with inline styles (what email programs understand). The plain-text
 * version is always sent alongside it, and the reports stay attachments.
 *
 * Untrusted: the subject and body (they hold client names) and every brand value (admin input). All text is escaped
 * with e(); colors are used only when they match #rrggbb (else the defaults). The logo is the PNG Sentinel re-encoded
 * itself (Branding), sent as an inline part referenced by cid:, because many email programs block data: images.
 */
final class ReportEmail
{
    /** Content-ID of the inline logo. */
    public const LOGO_CID = 'logo@msp-sentinel';

    /**
     * The HTML body and its inline images.
     *
     * @param string $logoPng the logo file's bytes, or '' for none
     * @return array{html:string, inline:list<array{cid:string, type:string, content:string}>}
     */
    public static function build(Settings $s, string $logoPng, string $subject, string $body): array
    {
        $b = ReportTheme::brand([
            'name' => $s->get('brand_name') !== '' ? $s->get('brand_name') : $s->get('product_name'),
            'color' => $s->get('brand_color'), 'accent' => $s->get('brand_accent'),
            'address' => $s->get('brand_address'), 'phone' => $s->get('brand_phone'), 'email' => $s->get('brand_email'), 'website' => $s->get('brand_website'),
            'footer' => $s->get('brand_footer'), 'logo_has_name' => $s->get('brand_logo_has_name') === '1',
        ]);
        $logo = str_starts_with($logoPng, "\x89PNG\r\n\x1a\n")
            ? '<img src="cid:' . self::LOGO_CID . '" alt="' . e($b['name']) . '" height="40" style="display:block;height:40px;max-width:180px;border:0">'
            : '';
        // The body: paragraphs separated by blank lines; lines starting with "- " become a list; the signature
        // ("-- " line) and everything after it is small print.
        [$main, $sig] = array_pad(preg_split("/\n-- \n/", str_replace("\r\n", "\n", $body), 2) ?: [''], 2, '');
        $html = '';
        foreach (preg_split("/\n{2,}/", trim($main)) ?: [] as $para) {
            $lines = explode("\n", $para);
            if (count(array_filter($lines, static fn (string $l): bool => str_starts_with($l, '- '))) === count($lines)) {
                $html .= '<ul style="margin:0 0 14px;padding-left:20px">' . implode('', array_map(static fn (string $l): string => '<li style="margin:2px 0">' . e(substr($l, 2)) . '</li>', $lines)) . '</ul>';
            } else {
                $html .= '<p style="margin:0 0 14px">' . implode('<br>', array_map('e', $lines)) . '</p>';
            }
        }
        $contact = array_values(array_filter([$b['address'], $b['phone'], $b['email'], $b['website']], static fn (string $v): bool => trim($v) !== ''));
        $font = 'font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif';
        $doc = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>' . e($subject) . '</title></head>'
            . '<body style="margin:0;padding:0;background:#eef1f5;' . $font . '">'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef1f5"><tr><td align="center" style="padding:24px 12px">'
            . '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background:#ffffff;border-radius:8px;overflow:hidden">'
            . '<tr><td style="background:' . $b['color'] . ';padding:18px 24px;border-bottom:4px solid ' . $b['accent'] . '">'
            . '<table role="presentation" cellpadding="0" cellspacing="0"><tr>'
            . ($logo !== '' ? '<td style="background:#ffffff;border-radius:6px;padding:6px 10px">' . $logo . '</td>' . ($b['logo_has_name'] ? '' : '<td width="14"></td>') : '')
            // A logo that already shows the company name (1.60) stands alone.
            . ($logo !== '' && $b['logo_has_name'] ? '' : '<td style="color:#ffffff;font-size:16px;font-weight:600;' . $font . '">' . e($b['name']) . '</td>') . '</tr></table></td></tr>'
            . '<tr><td style="padding:24px;color:#1b2430;font-size:14px;line-height:1.55;' . $font . '">'
            . '<h1 style="margin:0 0 16px;font-size:19px;line-height:1.3;color:#1b2430">' . e($subject) . '</h1>' . $html . '</td></tr>'
            . '<tr><td style="padding:16px 24px;background:#f4f6f9;color:#5d6673;font-size:12px;line-height:1.5;' . $font . '">'
            . ($contact !== [] ? '<strong style="color:#1b2430">' . e($b['name']) . '</strong><br>' . implode('<br>', array_map(static fn (string $v): string => str_replace("\n", "<br>", e($v)), $contact)) : '')
            . ($b['footer'] !== '' ? '<p style="margin:8px 0 0">' . str_replace("\n", "<br>", e($b['footer'])) . '</p>' : '')
            . (trim($sig) !== '' ? '<p style="margin:8px 0 0">' . e(trim($sig)) . '</p>' : '')
            . '</td></tr></table></td></tr></table></body></html>';
        return ['html' => $doc, 'inline' => $logo !== '' ? [['cid' => self::LOGO_CID, 'type' => 'image/png', 'content' => $logoPng]] : []];
    }
}

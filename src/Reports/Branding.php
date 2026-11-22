<?php

declare(strict_types=1);

namespace Sentinel\Reports;

/**
 * Stores the report logo safely.
 *
 * Security assumptions:
 * - The upload is untrusted. It must be a real PNG or JPEG (checked by
 *   decoding it with GD, not by its name or browser-sent type), at most 2 MB
 *   and 4000x4000 pixels. It is then RE-ENCODED as a fresh PNG (scaled to at
 *   most 600x200), which drops metadata and anything hidden in the file.
 * - The stored file is named after its SHA-256, in the app's storage
 *   directory (never the web root). Reports embed it as a data: URI.
 */
final class Branding
{
    private const MAX_BYTES = 2_000_000;
    private const MAX_INPUT_PIXELS = 4000;

    /** @param string $dir storage/branding */
    public function __construct(private readonly string $dir)
    {
    }

    /**
     * Process an uploaded file. Returns the logo hash, or [error message] (a one-item list).
     *
     * @param string $tmpPath Path of the uploaded temporary file.
     */
    public function storeLogo(string $tmpPath): string|array
    {
        if (!is_file($tmpPath) || filesize($tmpPath) === 0 || filesize($tmpPath) > self::MAX_BYTES) {
            return [__('The logo must be a PNG or JPEG file of at most 2 MB.')];
        }
        $info = @getimagesize($tmpPath);
        if ($info === false || !in_array($info[2], [IMAGETYPE_PNG, IMAGETYPE_JPEG], true)
            || $info[0] < 1 || $info[1] < 1 || $info[0] > self::MAX_INPUT_PIXELS || $info[1] > self::MAX_INPUT_PIXELS) {
            return [__('The logo must be a PNG or JPEG image of at most 4000×4000 pixels.')];
        }
        $src = $info[2] === IMAGETYPE_PNG ? @imagecreatefrompng($tmpPath) : @imagecreatefromjpeg($tmpPath);
        if ($src === false) {
            return [__('The logo image could not be read.')];
        }
        $scale = min(1, 600 / $info[0], 200 / $info[1]);
        $w = max(1, (int) round($info[0] * $scale));
        $h = max(1, (int) round($info[1] * $scale));
        $dst = imagecreatetruecolor($w, $h);
        imagealphablending($dst, false);
        imagesavealpha($dst, true);
        imagefill($dst, 0, 0, imagecolorallocatealpha($dst, 255, 255, 255, 127));
        imagecopyresampled($dst, $src, 0, 0, 0, 0, $w, $h, $info[0], $info[1]);
        ob_start();
        imagepng($dst, null, 9);
        $png = (string) ob_get_clean();
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            return [__('The logo could not be saved (storage folder not writable).')];
        }
        $hash = hash('sha256', $png);
        $file = $this->dir . '/logo-' . $hash . '.png';
        $tmp = $this->dir . '/.logo-' . bin2hex(random_bytes(8)) . '.tmp';
        if (@file_put_contents($tmp, $png) === false || !@rename($tmp, $file)) {
            @unlink($tmp);
            return [__('The logo could not be saved (storage folder not writable).')];
        }
        @chmod($file, 0600);
        return $hash;
    }

    /** The logo as a data: URI for previews, or '' if none. */
    public function dataUri(string $hash): string
    {
        if (!preg_match('/^[a-f0-9]{64}$/', $hash)) {
            return '';
        }
        $file = $this->dir . '/logo-' . $hash . '.png';
        return is_file($file) ? 'data:image/png;base64,' . base64_encode((string) file_get_contents($file)) : '';
    }
}

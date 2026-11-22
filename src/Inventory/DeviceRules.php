<?php

declare(strict_types=1);

namespace Sentinel\Inventory;

/**
 * Grading of internal devices (from inventory sources): unsupported OS,
 * antivirus, disk encryption, missing OS patches, and stale data.
 *
 * - Fail: Windows version without security updates; antivirus missing or off.
 * - Warning: antivirus definitions out of date; disk encryption off on a
 *   workstation; security or critical OS patches missing for more than 30
 *   days, or patches that failed to install.
 * - Info (shown, not a finding): encryption off on a server; device not seen
 *   by the source for 30 days or more (its data may be out of date).
 *
 * Untrusted: device data from the source; only compared with fixed values.
 */
final class DeviceRules
{
    /** Missing patches older than this become a finding. */
    public const PATCH_GRACE_DAYS = 30;
    /** A device the source hasn't heard from for this long is "stale". */
    public const STALE_DAYS = 30;

    /**
     * Issues for one device.
     *
     * @param array<string,mixed>       $device  devices row.
     * @param list<array<string,mixed>> $patches device_patches rows.
     * @return list<array{code:string, severity:string, text:string, detail:string}>
     */
    public static function issues(array $device, array $patches, ?int $now = null): array
    {
        $now ??= time();
        $out = [];
        $eos = OsLifecycle::endOfSupport((string) $device['os_name'], (string) $device['os_build']);
        if ($eos !== null && strtotime($eos . ' 23:59:59 UTC') < $now) {
            $out[] = ['code' => 'os_unsupported', 'severity' => 'fail', 'text' => __('Operating system no longer gets security updates'),
                      'detail' => __('{os} (build {build}): Microsoft security updates ended on {date}. If the device is enrolled in Extended Security Updates, mark this as an accepted risk.',
                          ['os' => $device['os_name'], 'build' => $device['os_build'] ?: '?', 'date' => $eos])];
        }
        $av = (string) $device['av_state'];
        if ($av === 'missing') {
            $out[] = ['code' => 'av_missing', 'severity' => 'fail', 'text' => __('No antivirus or EDR reported'), 'detail' => ''];
        } elseif ($av === 'off') {
            $out[] = ['code' => 'av_off', 'severity' => 'fail', 'text' => __('Antivirus or EDR is turned off'), 'detail' => (string) $device['av_product']];
        } elseif ((string) $device['av_definitions'] === 'outdated') {
            $out[] = ['code' => 'av_outdated', 'severity' => 'warn', 'text' => __('Antivirus definitions are out of date'), 'detail' => (string) $device['av_product']];
        }
        if ((string) $device['encryption'] === 'off') {
            $server = (string) $device['device_class'] === 'server';
            $out[] = ['code' => $server ? 'encryption_off_server' : 'encryption_off', 'severity' => $server ? 'info' : 'warn',
                      'text' => __('Disk encryption is off'), 'detail' => ''];
        }
        $late = [];
        $failed = [];
        foreach ($patches as $p) {
            if ((string) $p['status'] === 'failed') {
                $failed[] = $p;
            } elseif (in_array(strtolower((string) $p['severity']), ['critical', 'important', 'security', 'high'], true)
                // Missing since the source says it appeared, else since Sentinel first saw it missing.
                && ($since = $p['detected_at'] ?? $p['first_seen'] ?? null) !== null && strtotime($since . ' UTC') < $now - self::PATCH_GRACE_DAYS * 86400) {
                $late[] = $p;
            }
        }
        $list = static fn (array $ps): string => implode(', ', array_slice(array_map(static fn (array $p): string => (string) ($p['kb'] !== '' ? $p['kb'] : $p['name']), $ps), 0, 10))
            . (count($ps) > 10 ? ' …' : '');
        if ($late !== []) {
            $out[] = ['code' => 'patches_missing', 'severity' => 'warn', 'text' => __('Security updates missing for more than {d} days', ['d' => self::PATCH_GRACE_DAYS]),
                      'detail' => __('{n} update(s): {list}', ['n' => count($late), 'list' => $list($late)])];
        }
        if ($failed !== []) {
            $out[] = ['code' => 'patches_failed', 'severity' => 'warn', 'text' => __('Updates failed to install'),
                      'detail' => __('{n} update(s): {list}', ['n' => count($failed), 'list' => $list($failed)])];
        }
        if ($device['last_contact'] !== null && strtotime($device['last_contact'] . ' UTC') < $now - self::STALE_DAYS * 86400) {
            $out[] = ['code' => 'stale', 'severity' => 'info', 'text' => __('Not seen for {d} days or more: data may be out of date', ['d' => self::STALE_DAYS]), 'detail' => ''];
        }
        return $out;
    }

    /** Finding type for a code: missing/failed patches are "patch", the rest "device". */
    public static function type(string $code): string
    {
        return str_starts_with($code, 'patches_') ? 'patch' : 'device';
    }
}

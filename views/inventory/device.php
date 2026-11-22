<?php
/**
 * One internal device: status, problems, open findings, installed software (catalogue matches and CVEs) and missing updates.
 * Expects: $client, $device (with software, patches), $deviceFindings, $issues.
 * All device data comes from the inventory source (untrusted) and is escaped.
 */
require __DIR__ . '/../partials/finding_badges.php';
$chip = static function (string $sev, string $text): string {
    [$cls, $icon] = match ($sev) { 'fail' => ['danger', 'bi-x-octagon'], 'warn' => ['warning', 'bi-exclamation-triangle'], default => ['secondary', 'bi-info-circle'] };
    return '<span class="badge text-bg-' . $cls . ' me-1 mb-1 text-wrap text-start"><i class="bi ' . $icon . ' me-1" aria-hidden="true"></i>' . e($text) . '</span>';
};
$matched = array_values(array_filter($device['software'], static fn (array $s): bool => $s['cpe'] !== ''));
$other = count($device['software']) - count($matched);
?>
<p class="small"><a href="<?= e(url('/clients/' . (int) $client['id'] . '#devices')) ?>"><i class="bi bi-arrow-left me-1" aria-hidden="true"></i><?= e($client['name']) ?></a></p>
<div class="row g-3">
    <div class="col-lg-5">
        <div class="card mb-3">
            <div class="card-header"><h2 class="card-title h6 mb-0"><?= e(__('Device')) ?></h2></div>
            <div class="card-body small">
                <dl class="row mb-0">
                    <dt class="col-5"><?= e(__('Source')) ?></dt><dd class="col-7"><?= e($device['source']) ?> · <span class="font-monospace"><?= e($device['source_id']) ?></span></dd>
                    <dt class="col-5"><?= e(__('Operating system')) ?></dt><dd class="col-7"><?= e($device['os_name'] ?: '?') ?> <span class="font-monospace"><?= e($device['os_build']) ?></span></dd>
                    <dt class="col-5"><?= e(__('Addresses')) ?></dt><dd class="col-7 font-monospace"><?= e(str_replace(',', ', ', $device['ip_addresses']) ?: '-') ?></dd>
                    <dt class="col-5"><?= e(__('Antivirus / EDR')) ?></dt><dd class="col-7"><?= e(trim($device['av_product'] . ' ' . match ($device['av_state']) { 'on' => __('(on)'), 'off' => __('(off)'), 'missing' => __('none reported'), default => __('unknown') })) ?></dd>
                    <dt class="col-5"><?= e(__('Disk encryption')) ?></dt><dd class="col-7"><?= e(match ($device['encryption']) { 'on' => __('On'), 'off' => __('Off'), default => __('Unknown') }) ?></dd>
                    <dt class="col-5"><?= e(__('Last contact')) ?></dt><dd class="col-7"><?= e(($device['last_contact'] ?? '?') . ' UTC') ?></dd>
                </dl>
                <?php if ($device['removed_at'] !== null): ?><div class="alert alert-secondary mt-2 mb-0 py-2"><?= e(__('No longer reported by the source since {t} UTC.', ['t' => $device['removed_at']])) ?></div><?php endif; ?>
            </div>
        </div>
        <div class="card mb-3">
            <div class="card-header"><h2 class="card-title h6 mb-0"><?= e(__('Problems and findings')) ?></h2></div>
            <div class="card-body small">
                <?php if ($issues === [] && $deviceFindings === []): ?><span class="text-body-secondary"><?= e(__('No problems found.')) ?></span><?php endif; ?>
                <?php foreach ($issues as $i): ?><div><?= $chip($i['severity'], $i['text']) ?><?php if ($i['detail'] !== ''): ?><span class="text-body-secondary"><?= e($i['detail']) ?></span><?php endif; ?></div><?php endforeach; ?>
                <?php if ($deviceFindings !== []): ?><ul class="list-unstyled mt-2 mb-0"><?php foreach ($deviceFindings as $f): ?><li class="mb-1"><?= $findingSeverityBadge((string) $f['severity']) ?> <a href="<?= e(url('/findings/' . (int) $f['id'])) ?>"><?= e($f['title']) ?></a></li><?php endforeach; ?></ul><?php endif; ?>
            </div>
        </div>
        <div class="card">
            <div class="card-header"><h2 class="card-title h6 mb-0"><?= e(__('Missing updates')) ?></h2></div>
            <div class="card-body small p-0">
                <?php if ($device['patches'] === []): ?><p class="text-body-secondary p-3 mb-0"><?= e(__('None reported.')) ?></p><?php else: ?>
                <table class="table table-sm mb-0"><thead><tr><th><?= e(__('Update')) ?></th><th><?= e(__('Severity')) ?></th><th><?= e(__('Status')) ?></th><th><?= e(__('Since (UTC)')) ?></th></tr></thead><tbody>
                <?php foreach ($device['patches'] as $p): ?><tr><td><?= e($p['kb'] !== '' ? $p['kb'] . ' · ' : '') ?><?= e($p['name']) ?></td><td><?= e($p['severity'] ?: '-') ?></td><td><?= e($p['status'] === 'failed' ? __('Failed') : __('Pending')) ?></td><td class="text-nowrap"><?= e(substr((string) ($p['detected_at'] ?? ''), 0, 10) ?: '?') ?></td></tr><?php endforeach; ?>
                </tbody></table><?php endif; ?>
            </div>
        </div>
    </div>
    <div class="col-lg-7">
        <div class="card">
            <div class="card-header"><h2 class="card-title h6 mb-0"><?= e(__('Installed software')) ?></h2></div>
            <div class="card-body small p-0">
                <p class="text-body-secondary px-3 pt-3"><?= e(__('Programs in Sentinel\'s software catalogue are matched to known vulnerabilities for the installed version. {n} other program(s) are listed but not matched (not in the catalogue).', ['n' => $other])) ?></p>
                <table class="table table-sm mb-0"><thead><tr><th><?= e(__('Program')) ?></th><th><?= e(__('Version')) ?></th><th><?= e(__('Vulnerabilities')) ?></th></tr></thead><tbody>
                <?php foreach ($device['software'] as $s): ?>
                <tr><td><?= e($s['name']) ?><?php if ($s['publisher'] !== ''): ?><div class="text-body-secondary"><?= e($s['publisher']) ?></div><?php endif; ?></td>
                    <td class="font-monospace"><?= e($s['version']) ?></td>
                    <td><?php if ($s['cpe'] === ''): ?><span class="text-body-secondary"><?= e(__('not matched')) ?></span>
                        <?php elseif ((string) $s['cves'] === ''): ?><span class="text-body-secondary"><?= e(__('none known')) ?></span>
                        <?php else: ?><?php foreach (array_slice(explode(',', (string) $s['cves']), 0, 8) as $cve): ?><a class="badge text-bg-danger me-1" href="https://nvd.nist.gov/vuln/detail/<?= e(rawurlencode($cve)) ?>" target="_blank" rel="noopener noreferrer"><?= e($cve) ?></a><?php endforeach; ?><?php endif; ?></td></tr>
                <?php endforeach; ?>
                </tbody></table>
            </div>
        </div>
    </div>
</div>

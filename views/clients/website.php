<?php
/**
 * Website and email security card on the client page.
 * Expects: $websiteChecks (WebsiteRepository::checksForClient), $emailChecks (emailForClient).
 * Everything shown comes from scanned sites and DNS (untrusted) and is escaped.
 * Each status has an icon and a word, never colour alone.
 */
use Sentinel\Scanning\ExposureRules;

$chip = static function (string $sev, string $text): string {
    [$cls, $icon] = match ($sev) { 'fail' => ['danger', 'bi-x-octagon'], 'warn' => ['warning', 'bi-exclamation-triangle'], 'ok' => ['success', 'bi-check-circle'], default => ['secondary', 'bi-info-circle'] };
    return '<span class="badge text-bg-' . $cls . ' me-1 mb-1 text-wrap text-start"><i class="bi ' . $icon . ' me-1" aria-hidden="true"></i>' . e($text) . '</span>';
};
?>
<div class="card mb-3" id="website">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Website and email security')) ?></h2></div>
    <div class="card-body">
        <p class="small text-body-secondary"><?= e(__('Checked after each port scan and daily, on every web service in scope: HTTPS and redirects, security headers, cookies, CMS and JavaScript library versions, and a short fixed list of commonly exposed files (only reported when their content proves it). Email records are checked through DNS only.')) ?></p>
        <h3 class="h6"><?= e(__('Websites')) ?></h3>
        <?php if ($websiteChecks === []): ?>
        <p class="small text-body-secondary"><?= e(__('No web services checked yet.')) ?></p>
        <?php else: ?>
        <div class="table-responsive">
        <table class="table table-sm align-middle small">
            <thead><tr><th><?= e(__('Address')) ?></th><th><?= e(__('Problems')) ?></th><th><?= e(__('Detected software')) ?></th></tr></thead>
            <tbody>
            <?php foreach ($websiteChecks as $w):
                $codes = array_unique(array_merge((array) ($w['checks']['issues'] ?? []), (array) ($w['checks']['exposed'] ?? []))); ?>
            <tr>
                <td><code><?= e(($w['scheme'] ?? 'http') . '://' . $w['ip'] . ':' . $w['port']) ?></code><?php if ($w['host_header'] !== ''): ?><br><span class="text-body-secondary"><?= e($w['host_header']) ?></span><?php endif; ?><br><span class="text-body-secondary"><?= e(__('Checked {time} UTC', ['time' => (string) $w['checks_at']])) ?></span></td>
                <td><?php if ($codes === []): ?><?= $chip('ok', __('No problems found')) ?><?php endif; ?>
                    <?php foreach ($codes as $code): $r = ExposureRules::websiteIssue((string) $code); ?><?= $chip($r['severity'], $r['text']) ?><?php endforeach; ?>
                    <?php $advice = (array) ($w['checks']['info'] ?? []); if ($advice !== []): ?>
                    <div class="text-body-secondary mt-1"><i class="bi bi-info-circle me-1" aria-hidden="true"></i><?= e(__('Advice')) ?>: <?= e(implode('; ', array_map(static fn ($c): string => ExposureRules::websiteIssue((string) $c)['text'], $advice))) ?></div>
                    <?php endif; ?></td>
                <td><?php foreach ($w['components'] as $c): ?><span class="d-block"><?= e($c['name']) ?> <span class="font-monospace"><?= e($c['version'] !== '' ? $c['version'] : __('version unknown')) ?></span></span><?php endforeach; ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
        <?php endif; ?>
        <h3 class="h6 mt-2"><?= e(__('Email (SPF, DMARC, DKIM)')) ?></h3>
        <?php if ($emailChecks === []): ?>
        <p class="small text-body-secondary mb-0"><?= e(__('No domains checked yet. Domains come from the client\'s authorisation.')) ?></p>
        <?php else: ?>
        <div class="table-responsive">
        <table class="table table-sm align-middle small mb-0">
            <thead><tr><th><?= e(__('Domain')) ?></th><th><?= e(__('Result')) ?></th><th><?= e(__('Records')) ?></th></tr></thead>
            <tbody>
            <?php foreach ($emailChecks as $m): ?>
            <tr>
                <td><code><?= e($m['domain'] ?? '') ?></code></td>
                <td><?php if (empty($m['has_mx'])): ?><?= $chip('info', __('Receives no email (no MX): not judged')) ?>
                    <?php else: ?><?php if (($m['issues'] ?? []) === []): ?><?= $chip('ok', __('SPF and DMARC in place')) ?><?php endif; ?>
                    <?php foreach ((array) ($m['issues'] ?? []) as $code): $r = ExposureRules::emailIssue((string) $code); ?><?= $chip($r['severity'], $r['text']) ?><?php endforeach; ?>
                    <?php foreach ((array) ($m['info'] ?? []) as $code): ?><?= $chip('info', ExposureRules::emailIssue((string) $code)['text']) ?><?php endforeach; ?><?php endif; ?></td>
                <td class="text-break sn-records"><?php if (($m['spf'] ?? '') !== ''): ?><span class="d-block"><b>SPF</b> <code><?= e($m['spf']) ?></code></span><?php endif; ?>
                    <?php if (($m['dmarc'] ?? '') !== ''): ?><span class="d-block"><b>DMARC</b> <code><?= e($m['dmarc']) ?></code></span><?php endif; ?>
                    <?php if (!empty($m['dkim'])): ?><span class="d-block"><b>DKIM</b> <?= e(implode(', ', (array) $m['dkim'])) ?></span><?php endif; ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
        <?php endif; ?>
    </div>
</div>

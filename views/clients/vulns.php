<?php
/**
 * Vulnerabilities panel on the client's pages.
 * Expects: $vulns (rows from VulnRepository::forClient, most important first), $feeds (feed status rows),
 *          $vulnCoverage (waiting/failed/no_product counts, so "nothing matched" is never overstated).
 * Shows KEV and critical/high first; lower severities are counted and can be expanded.
 * All values are escaped. CVE IDs are validated when stored.
 */
use Sentinel\Scanning\ExposureRules;

$important = [];
$other = [];
foreach ($vulns as $v) {
    $v['sev'] = ExposureRules::vulnSeverity($v);
    if ($v['sev'] !== 'info' || in_array($v['cvss_severity'], ['CRITICAL', 'HIGH'], true)) {
        $important[] = $v;
    } else {
        $other[] = $v;
    }
}
$sevStyle = ['fail' => ['text-bg-danger', 'bi-x-octagon', __('Fail')], 'warn' => ['text-bg-warning', 'bi-exclamation-triangle', __('Warning')], 'info' => ['text-bg-secondary', 'bi-info-circle', __('Info')]];
$row = static function (array $v) use ($sevStyle): string {
    [$cls, $icon, $label] = $sevStyle[$v['sev']];
    $out = '<tr><td><span class="badge ' . e($cls) . ' me-1"><i class="bi ' . e($icon) . ' me-1" aria-hidden="true"></i>' . e($label) . '</span>';
    $out .= '<a class="text-nowrap" href="https://nvd.nist.gov/vuln/detail/' . rawurlencode((string) $v['cve_id']) . '" target="_blank" rel="noopener noreferrer">' . e($v['cve_id']) . '</a>';
    if ((int) $v['in_kev'] === 1) {
        $out .= '<div class="mt-1"><span class="badge text-bg-danger"><i class="bi bi-lightning-charge me-1" aria-hidden="true"></i>' . e(__('Known exploited')) . '</span>'
            . ($v['ransomware'] === 'Known' ? ' <span class="badge text-bg-dark">' . e(__('Used by ransomware')) . '</span>' : '') . '</div>';
    }
    $out .= '</td><td><code>' . e($v['ip']) . ':' . e($v['port']) . '</code><div class="small text-body-secondary">' . e(trim($v['product'] . ' ' . $v['version'])) . '</div></td>';
    $out .= '<td class="small text-nowrap">' . ($v['cvss_score'] !== null ? e($v['cvss_score'] . ' ' . ucfirst(strtolower((string) $v['cvss_severity']))) : '—')
        . ($v['epss'] !== null ? '<div class="text-body-secondary">' . e(__('EPSS {p}%', ['p' => round((float) $v['epss'] * 100, 1)])) . '</div>' : '') . '</td>';
    $label = match ($v['confidence']) {
        'confirmed' => __('Confirmed: reported version is affected'),
        'distro' => __('Distribution build: the fix may be backported, check the distribution\'s security notices'),
        default => __('Product found, version unknown'),
    };
    $out .= '<td class="small vuln-summary"><span class="badge text-bg-light border text-wrap text-start">' . e($label) . '</span>'
        . '<div class="text-body-secondary mt-1">' . e(mb_strimwidth((string) $v['summary'], 0, 220, '…')) . '</div></td></tr>';
    return $out;
};
$kevUpdated = $feeds['kev']['last_success'] ?? null;
?>
<div class="card mt-3" id="vulns">
    <div class="card-header d-flex align-items-center flex-wrap gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('Vulnerabilities')) ?></h2>
        <span class="small text-body-secondary ms-auto"><?= e($kevUpdated !== null ? __('Known-exploited list updated {d} UTC', ['d' => $kevUpdated]) : __('Vulnerability data has not been downloaded yet: it starts automatically within a few minutes of installing.')) ?></span>
    </div>
    <div class="card-body">
        <p class="small text-body-secondary"><?= e(__('Matched from the product and version each service reports, using NVD, the CISA list of known exploited vulnerabilities and EPSS exploit-likelihood scores. "Confirmed" means the reported version is affected; banners can be wrong. Without a version, only known-exploited issues are shown, marked as possible.')) ?></p>
        <?php if ($vulnCoverage['waiting'] + $vulnCoverage['failed'] + $vulnCoverage['no_product'] > 0): ?>
        <p class="small mb-2"><i class="bi bi-info-circle me-1" aria-hidden="true"></i><?= e(__('Coverage: {w} product(s) waiting for vulnerability data, {f} lookup(s) failed, {n} open service(s) without product information (not matched).', ['w' => $vulnCoverage['waiting'], 'f' => $vulnCoverage['failed'], 'n' => $vulnCoverage['no_product']])) ?></p>
        <?php endif; ?>
        <?php if ($vulns === []): ?>
        <p class="text-body-secondary small mb-0"><?= e(__('No known vulnerabilities matched for the products identified.')) ?></p>
        <?php else: ?>
        <?php if ($important !== []): ?>
        <div class="table-responsive">
        <table class="table table-sm align-middle">
            <thead><tr><th scope="col"><?= e(__('Grade and CVE')) ?></th><th scope="col"><?= e(__('Service')) ?></th><th scope="col"><?= e(__('Severity')) ?></th><th scope="col"><?= e(__('Match and summary')) ?></th></tr></thead>
            <tbody><?php foreach ($important as $v): ?><?= $row($v) ?><?php endforeach; ?></tbody>
        </table>
        </div>
        <?php else: ?>
        <p class="small mb-2"><?= e(__('No known-exploited, critical or high vulnerabilities matched.')) ?></p>
        <?php endif; ?>
        <?php if ($other !== []): ?>
        <details class="small">
            <summary><?= e(__('+{n} lower-severity vulnerabilities', ['n' => count($other)])) ?></summary>
            <div class="table-responsive mt-2">
            <table class="table table-sm align-middle mb-0"><tbody><?php foreach ($other as $v): ?><?= $row($v) ?><?php endforeach; ?></tbody></table>
            </div>
        </details>
        <?php endif; ?>
        <?php endif; ?>
    </div>
</div>

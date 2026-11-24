<?php
/**
 * Certificates and web pages panel on the client's pages.
 * Expects: $tlsEndpoints, $webPages (rows from EndpointRepository).
 * Every value here came from a remote server (certificate fields, titles, headers): always escaped.
 * Issues come from ExposureRules, so they match the findings step later.
 */
use Sentinel\Scanning\ExposureRules;

$sevBadge = [
    'fail' => ['text-bg-danger', 'bi-x-octagon'],
    'warn' => ['text-bg-warning', 'bi-exclamation-triangle'],
    'info' => ['text-bg-secondary', 'bi-info-circle'],
];
$badge = static function (string $severity, string $text) use ($sevBadge): string {
    [$cls, $icon] = $sevBadge[$severity] ?? $sevBadge['info'];
    $label = ['fail' => __('Fail'), 'warn' => __('Warning'), 'info' => __('Info')][$severity] ?? '';
    return '<span class="badge ' . e($cls) . ' text-wrap text-start me-1 mb-1"><i class="bi ' . e($icon) . ' me-1" aria-hidden="true"></i>'
        . '<span class="visually-hidden">' . e($label) . ': </span>' . e($text) . '</span>';
};
?>
<div class="card mt-3" id="exposure">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Certificates and web pages')) ?></h2></div>
    <div class="card-body">
        <p class="small text-body-secondary"><?= e(__('Checked after each port scan and once a day: one short TLS connection per certificate (plus two to see whether old TLS versions are still accepted) and one request for the start page of each web port. No logins, no guessing.')) ?></p>

        <h3 class="h6"><?= e(__('TLS certificates')) ?></h3>
        <?php if ($tlsEndpoints === []): ?>
        <p class="small text-body-secondary"><?= e(__('No TLS services checked yet.')) ?></p>
        <?php else: ?>
        <div class="table-responsive">
        <table class="table table-sm align-middle">
            <thead><tr>
                <th scope="col"><?= e(__('Endpoint')) ?></th><th scope="col"><?= e(__('Certificate')) ?></th>
                <th scope="col"><?= e(__('Expires')) ?></th><th scope="col"><?= e(__('Issues')) ?></th>
            </tr></thead>
            <tbody>
            <?php foreach ($tlsEndpoints as $t): ?>
            <?php $issues = ExposureRules::tlsIssues($t); ?>
            <tr>
                <td><code><?= e($t['ip']) ?>:<?= e($t['port']) ?></code><?php if ($t['sni'] !== ''): ?><div class="small text-body-secondary"><?= e($t['sni']) ?></div><?php endif; ?></td>
                <td class="small">
                    <?php if ($t['not_after'] === null && $t['subject_cn'] === '' && $t['issuer'] === ''): ?>
                    <span class="text-body-secondary"><?= e(__('No certificate read (not reachable at the last check)')) ?></span>
                    <?php else: ?>
                    <?= e($t['subject_cn'] !== '' ? $t['subject_cn'] : '—') ?>
                    <div class="text-body-secondary"><?= e(__('Issuer: {i}', ['i' => $t['issuer'] !== '' ? $t['issuer'] : '?'])) ?> · <?= e(trim($t['key_type'] . ' ' . ($t['key_bits'] ?? ''))) ?> · <?= e($t['protocol']) ?></div>
                    <?php endif; ?>
                    <?php if ($t['last_error'] !== ''): ?><div class="text-danger"><?= e($t['last_error']) ?></div><?php endif; ?>
                </td>
                <td class="small text-nowrap"><?= e(when($t['not_after'] ?? null, null, '—')) ?></td>
                <td>
                    <?php foreach ($issues as $issue): ?><?= $badge($issue['severity'], $issue['text']) ?><?php endforeach; ?>
                    <?php if ($issues === [] && $t['not_after'] !== null): ?><span class="badge text-bg-success"><i class="bi bi-check-circle me-1" aria-hidden="true"></i><?= e(__('OK')) ?></span><?php endif; ?>
                    <?php if ($issues === [] && $t['not_after'] === null): ?><span class="badge text-bg-secondary"><?= e(__('Not reachable')) ?></span><?php endif; ?>
                    <div class="small text-body-secondary"><?= e(__('Checked {date}', ['date' => $t['last_checked']])) ?></div>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
        <?php endif; ?>

        <h3 class="h6 mt-2"><?= e(__('Web pages')) ?></h3>
        <?php if ($webPages === []): ?>
        <p class="small text-body-secondary mb-0"><?= e(__('No web pages checked yet.')) ?></p>
        <?php else: ?>
        <div class="table-responsive">
        <table class="table table-sm align-middle mb-0">
            <thead><tr>
                <th scope="col"><?= e(__('Address')) ?></th><th scope="col"><?= e(__('Page')) ?></th><th scope="col"><?= e(__('Detected as')) ?></th>
            </tr></thead>
            <tbody>
            <?php foreach ($webPages as $w): ?>
            <?php $issue = ExposureRules::webIssue($w['category']); ?>
            <tr>
                <td><code><?= e($w['scheme']) ?>://<?= e($w['ip']) ?>:<?= e($w['port']) ?></code><?php if ($w['host_header'] !== ''): ?><div class="small text-body-secondary"><?= e($w['host_header']) ?></div><?php endif; ?></td>
                <td class="small">
                    <?php $unreachable = ($w['status_code'] ?? null) === null; ?>
                    <?= e($unreachable ? __('No answer (not reachable at the last check)') : ($w['title'] !== '' ? $w['title'] : __('(no title)'))) ?>
                    <div class="text-body-secondary"><?= $unreachable ? '' : e(__('HTTP {code}', ['code' => $w['status_code']])) ?><?= $w['server_header'] !== '' ? ' · ' . e($w['server_header']) : '' ?><?= $w['redirect_to'] !== '' ? ' · ' . e(__('redirects to {url}', ['url' => $w['redirect_to']])) : '' ?></div>
                    <?php if ($w['last_error'] !== ''): ?><div class="text-danger"><?= e($w['last_error']) ?></div><?php endif; ?>
                </td>
                <td><?= $issue !== null ? $badge($issue['severity'], $issue['text']) : ($unreachable ? '<span class="badge text-bg-secondary">' . e(__('Not reachable')) . '</span>' : '<span class="small text-body-secondary">' . e(__('Nothing notable')) . '</span>') ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
        <?php endif; ?>
    </div>
</div>

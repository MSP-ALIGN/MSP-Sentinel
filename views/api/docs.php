<?php
/**
 * The API reference for admins (1.34): the OpenAPI description as a readable page.
 * Expects: $spec (OpenApi::spec(), static text built by Sentinel). Every value is escaped.
 */
$paths = (array) ($spec['paths'] ?? []);
$methodClass = static fn (string $m): string => $m === 'get' ? 'text-bg-primary' : 'text-bg-warning';
?>
<div class="card mb-3">
    <div class="card-body">
        <p class="mb-2"><?= nl2br(e((string) ($spec['info']['description'] ?? ''))) ?></p>
        <p class="small text-body-secondary mb-2"><?= e(__('Base address: {u} on this server. Create a token under Administration → API; it is sent as "Authorization: Bearer snt_...".', ['u' => url('/api/v1')])) ?></p>
        <a class="btn btn-outline-secondary btn-sm" href="<?= e(url('/admin/api/docs?format=json')) ?>"><i class="bi bi-download me-1" aria-hidden="true"></i><?= e(__('Download OpenAPI JSON')) ?></a>
        <a class="btn btn-outline-secondary btn-sm" href="<?= e(url('/admin/api')) ?>"><?= e(__('Back to API tokens')) ?></a>
    </div>
</div>
<div class="mb-3"><label class="visually-hidden" for="api-filter"><?= e(__('Filter endpoints')) ?></label>
    <input type="search" class="form-control" id="api-filter" data-filter-list="#api-endpoints" placeholder="<?= e(__('Filter endpoints, e.g. findings')) ?>"></div>
<div id="api-endpoints">
<?php foreach ($paths as $path => $ops): foreach ((array) $ops as $method => $op): ?>
<div class="card mb-2" data-filter-item>
    <div class="card-header d-flex flex-wrap align-items-center gap-2">
        <span class="badge <?= e($methodClass((string) $method)) ?>"><?= e(strtoupper((string) $method)) ?></span>
        <code><?= e('/api/v1' . $path) ?></code>
        <span class="text-body-secondary small"><?= e((string) ($op['summary'] ?? '')) ?></span>
    </div>
    <div class="card-body small">
        <?php $params = (array) ($op['parameters'] ?? []); if ($params !== []): ?>
        <table class="table table-sm mb-2">
            <thead><tr><th><?= e(__('Parameter')) ?></th><th><?= e(__('In')) ?></th><th><?= e(__('Type / values')) ?></th><th><?= e(__('Notes')) ?></th></tr></thead>
            <tbody>
            <?php foreach ($params as $p): $sch = (array) ($p['schema'] ?? []); ?>
            <tr><td><code><?= e((string) ($p['name'] ?? '')) ?></code><?= !empty($p['required']) ? ' <span class="badge text-bg-secondary">' . e(__('required')) . '</span>' : '' ?></td>
                <td><?= e((string) ($p['in'] ?? '')) ?></td>
                <td><?= e(isset($sch['enum']) ? implode(' | ', (array) $sch['enum']) : (string) ($sch['type'] ?? '')) ?><?= isset($sch['default']) ? ' · ' . e(__('default {d}', ['d' => (string) $sch['default']])) : '' ?></td>
                <td><?= e((string) ($p['description'] ?? '')) ?></td></tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
        <?php $body = $op['requestBody']['content']['application/json']['schema'] ?? null; if (is_array($body)): ?>
        <p class="mb-1"><?= e(__('JSON body:')) ?> <?php foreach ((array) ($body['properties'] ?? []) as $name => $prop): ?><code><?= e((string) $name) ?></code> (<?= e(isset($prop['enum']) ? implode(' | ', (array) $prop['enum']) : (string) ($prop['type'] ?? '')) ?>) <?php endforeach; ?></p>
        <?php endif; ?>
        <p class="mb-0 text-body-secondary"><?= e(__('Answers:')) ?> <?php foreach ((array) ($op['responses'] ?? []) as $code => $r): ?><span class="me-2"><strong><?= e((string) $code) ?></strong> <?= e((string) ($r['description'] ?? '')) ?></span><?php endforeach; ?></p>
    </div>
</div>
<?php endforeach; endforeach; ?>
</div>

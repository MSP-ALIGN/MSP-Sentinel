<?php
/**
 * Record a scan authorisation.
 * Expects: $client, $values (untrusted strings), $errors (field => message), $scopeErrors (list of messages).
 */
use Sentinel\Core\Csrf;
use Sentinel\Scope\ScopeParser;

$invalid = static fn (string $f): string => !empty($errors[$f]) ? ' is-invalid' : '';
?>
<p class="text-body-secondary"><?= e(__('Client: {name}', ['name' => $client['name']])) ?></p>
<?php if (($values['replaces'] ?? '') !== ''): ?>
<div class="alert alert-info">
    <i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i>
    <?= e(__('This new authorization will replace authorization(s) #{ids}. They will be revoked when you save. The scope below starts with the current scope.', ['ids' => str_replace(',', ', #', $values['replaces'])])) ?>
    <?php if (!empty($added)): ?>
    <div class="mt-1"><?= e(__('Added from discovery: {list}. Make sure the client has approved these too.', ['list' => implode(', ', $added)])) ?></div>
    <?php endif; ?>
</div>
<?php endif; ?>
<form method="post" action="<?= e(url('/clients/' . (int) $client['id'] . '/authorisations')) ?>" novalidate>
<?= Csrf::field() ?>
<input type="hidden" name="replaces" value="<?= e($values['replaces'] ?? '') ?>">
<div class="row g-3">
    <div class="col-lg-6">
        <div class="card h-100">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Who approved it')) ?></h2></div>
            <div class="card-body">
                <div class="mb-3">
                    <label for="approved_by_name" class="form-label"><?= e(__('Name of the person at the client')) ?></label>
                    <input type="text" class="form-control<?= $invalid('approved_by_name') ?>" id="approved_by_name" name="approved_by_name" value="<?= e($values['approved_by_name']) ?>" maxlength="150" required>
                    <?php $field = 'approved_by_name'; require __DIR__ . '/../partials/field_error.php'; ?>
                </div>
                <div class="mb-3">
                    <label for="approved_by_role" class="form-label"><?= e(__('Their role')) ?></label>
                    <input type="text" class="form-control<?= $invalid('approved_by_role') ?>" id="approved_by_role" name="approved_by_role" value="<?= e($values['approved_by_role']) ?>" maxlength="150" required>
                    <div class="form-text"><?= e(__('Someone with the authority to approve scanning of these systems, e.g. the owner or IT manager.')) ?></div>
                    <?php $field = 'approved_by_role'; require __DIR__ . '/../partials/field_error.php'; ?>
                </div>
                <div class="row g-3">
                    <div class="col-md-4">
                        <label for="approved_on" class="form-label"><?= e(__('Approved on')) ?></label>
                        <input type="date" class="form-control<?= $invalid('approved_on') ?>" id="approved_on" name="approved_on" value="<?= e($values['approved_on']) ?>" required>
                        <?php $field = 'approved_on'; require __DIR__ . '/../partials/field_error.php'; ?>
                    </div>
                    <div class="col-md-4">
                        <label for="valid_from" class="form-label"><?= e(__('Valid from')) ?></label>
                        <input type="date" class="form-control<?= $invalid('valid_from') ?>" id="valid_from" name="valid_from" value="<?= e($values['valid_from']) ?>" required>
                        <?php $field = 'valid_from'; require __DIR__ . '/../partials/field_error.php'; ?>
                    </div>
                    <div class="col-md-4">
                        <label for="valid_until" class="form-label"><?= e(__('Valid until')) ?></label>
                        <input type="date" class="form-control<?= $invalid('valid_until') ?>" id="valid_until" name="valid_until" value="<?= e($values['valid_until']) ?>" required>
                        <?php $field = 'valid_until'; require __DIR__ . '/../partials/field_error.php'; ?>
                    </div>
                    <div class="col-12 form-text mt-1"><?= e(__('At most 2 years. Dates are in the client\'s timezone ({tz}).', ['tz' => $client['timezone']])) ?></div>
                </div>
                <div class="mt-3 mb-3">
                    <label for="document_ref" class="form-label"><?= e(__('Document reference (optional)')) ?></label>
                    <input type="text" class="form-control<?= $invalid('document_ref') ?>" id="document_ref" name="document_ref" value="<?= e($values['document_ref']) ?>" maxlength="190">
                    <div class="form-text"><?= e(__('Where the signed authorization is kept, e.g. a ticket number or document name.')) ?></div>
                    <?php $field = 'document_ref'; require __DIR__ . '/../partials/field_error.php'; ?>
                </div>
                <div>
                    <label for="notes" class="form-label"><?= e(__('Notes (optional)')) ?></label>
                    <textarea class="form-control<?= $invalid('notes') ?>" id="notes" name="notes" rows="2" maxlength="2000"><?= e($values['notes']) ?></textarea>
                    <?php $field = 'notes'; require __DIR__ . '/../partials/field_error.php'; ?>
                </div>
            </div>
        </div>
    </div>
    <div class="col-lg-6">
        <div class="card h-100">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('What may be scanned')) ?></h2></div>
            <div class="card-body">
                <?php if ($scopeErrors !== []): ?>
                <div class="alert alert-danger small" role="alert">
                    <ul class="mb-0 ps-3"><?php foreach ($scopeErrors as $msg): ?><li><?= e($msg) ?></li><?php endforeach; ?></ul>
                </div>
                <?php endif; ?>
                <label for="scope" class="form-label"><?= e(__('Scope: one entry per line')) ?></label>
                <textarea class="form-control font-monospace<?= $scopeErrors !== [] ? ' is-invalid' : '' ?>" id="scope" name="scope" rows="10" required spellcheck="false"><?= e($values['scope']) ?></textarea>
                <div class="form-text">
                    <?= e(__('Public IP addresses (203.0.113.10), ranges up to /24 (198.51.100.0/24) and domains (client-domain.com, or *.client-domain.com for all subdomains). Up to {n} entries. Lines starting with # are ignored.', ['n' => ScopeParser::MAX_ENTRIES])) ?>
                </div>
                <div class="form-text"><?= e(__('Private and internal addresses are refused here: this register is for scans from the internet. Internal networks are approved per site on the client\'s Agents page.')) ?></div>
            </div>
        </div>
    </div>
</div>
<div class="card mt-3">
    <div class="card-body">
        <div class="form-check">
            <input class="form-check-input<?= $invalid('confirm') ?>" type="checkbox" value="1" id="confirm" name="confirm" <?= $values['confirm'] === '1' ? 'checked' : '' ?>>
            <label class="form-check-label" for="confirm"><?= e(__('I confirm that this client has authorized us to scan exactly these systems for these dates, and that the authorization is documented.')) ?></label>
            <?php $field = 'confirm'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
        <p class="small text-body-secondary mt-2 mb-0"><?= e(__('Authorizations cannot be edited after saving. To change the scope later, revoke this one and record a new one.')) ?></p>
    </div>
    <div class="card-footer">
        <button type="submit" class="btn btn-primary"><i class="bi bi-file-earmark-check me-1" aria-hidden="true"></i><?= e(__('Record authorization')) ?></button>
        <a href="<?= e(url('/clients/' . (int) $client['id'])) ?>" class="btn btn-outline-secondary"><?= e(__('Cancel')) ?></a>
    </div>
</div>
</form>

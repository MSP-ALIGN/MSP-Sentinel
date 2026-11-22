<?php
/**
 * Record an internal authorisation for a site (admins). The ranges must be private networks; the saved
 * authorisation is signed and can only be revoked, never edited.
 * Expects: $client, $site, $values, $errors.
 */
use Sentinel\Core\Csrf;

$invalid = static fn (string $f): string => !empty($errors[$f]) ? ' is-invalid' : '';
?>
<div class="card">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Internal authorisation: {client}, {site}', ['client' => $client['name'], 'site' => $site['name']])) ?></h2></div>
    <form method="post" action="<?= e(url('/clients/' . (int) $client['id'] . '/sites/' . (int) $site['id'] . '/internal-authorisations')) ?>" novalidate>
    <div class="card-body">
        <?= Csrf::field() ?>
        <p class="small text-body-secondary"><?= e(__('Record who at the client approved scanning their internal networks, for how long, and exactly which networks. Sentinel signs this authorisation; agents refuse to scan anything outside it.')) ?></p>
        <div class="row g-3">
            <?php foreach (['approved_by_name' => __('Approved by (name)'), 'approved_by_role' => __('Their role')] as $f => $label): ?>
            <div class="col-md-6"><label class="form-label" for="<?= e($f) ?>"><?= e($label) ?></label>
                <input class="form-control<?= $invalid($f) ?>" id="<?= e($f) ?>" name="<?= e($f) ?>" value="<?= e($values[$f]) ?>" maxlength="150" required>
                <?php $field = $f; require __DIR__ . '/../partials/field_error.php'; ?></div>
            <?php endforeach; ?>
            <?php foreach (['approved_on' => __('Approved on'), 'valid_from' => __('Valid from'), 'valid_until' => __('Valid until')] as $f => $label): ?>
            <div class="col-md-4"><label class="form-label" for="<?= e($f) ?>"><?= e($label) ?></label>
                <input type="date" class="form-control<?= $invalid($f) ?>" id="<?= e($f) ?>" name="<?= e($f) ?>" value="<?= e($values[$f]) ?>" required>
                <?php $field = $f; require __DIR__ . '/../partials/field_error.php'; ?></div>
            <?php endforeach; ?>
            <div class="col-12"><label class="form-label" for="ranges"><?= e(__('Internal networks (one per line)')) ?></label>
                <textarea class="form-control font-monospace<?= $invalid('ranges') ?>" id="ranges" name="ranges" rows="5" placeholder="10.20.0.0/16&#10;192.168.1.0/24&#10;# comments are allowed"><?= e($values['ranges']) ?></textarea>
                <div class="form-text"><?= e(__('Private addresses only (10.x, 172.16-31.x, 192.168.x, fc00::/7). Each network at most a /16; at most four /16 in total.')) ?></div>
                <?php if (!empty($errors['ranges'])): ?><div class="invalid-feedback d-block text-pre-line"><?= e($errors['ranges']) ?></div><?php endif; ?></div>
            <div class="col-md-6"><label class="form-label" for="document_ref"><?= e(__('Document reference (optional)')) ?></label>
                <input class="form-control<?= $invalid('document_ref') ?>" id="document_ref" name="document_ref" value="<?= e($values['document_ref']) ?>" maxlength="190">
                <?php $field = 'document_ref'; require __DIR__ . '/../partials/field_error.php'; ?></div>
            <div class="col-md-6"><label class="form-label" for="notes"><?= e(__('Notes (optional)')) ?></label>
                <textarea class="form-control<?= $invalid('notes') ?>" id="notes" name="notes" rows="2" maxlength="2000"><?= e($values['notes']) ?></textarea>
                <?php $field = 'notes'; require __DIR__ . '/../partials/field_error.php'; ?></div>
            <div class="col-12"><div class="form-check">
                <input class="form-check-input<?= $invalid('confirm') ?>" type="checkbox" id="confirm" name="confirm" value="1" <?= $values['confirm'] === '1' ? 'checked' : '' ?>>
                <label class="form-check-label" for="confirm"><?= e(__('The client approved scanning exactly these internal networks for these dates.')) ?></label>
                <?php $field = 'confirm'; require __DIR__ . '/../partials/field_error.php'; ?></div></div>
        </div>
    </div>
    <div class="card-footer d-flex gap-2"><button class="btn btn-primary" type="submit"><?= e(__('Record and sign')) ?></button>
        <a class="btn btn-outline-secondary" href="<?= e(url('/clients/' . (int) $client['id'] . '/agents')) ?>"><?= e(__('Cancel')) ?></a></div>
    </form>
</div>

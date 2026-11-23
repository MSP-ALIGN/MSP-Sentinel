<?php
/**
 * New pen-test engagement (multipart: the client's signed authorisation, a PDF).
 * Expects: $client, $values (untrusted strings), $errors (field => message), $sites (site, its active internal ranges
 * and their end date), $scope (the client's active external scope entries), $testLabels, $earlier (approved engagements).
 * Every value is escaped.
 */
use Sentinel\Core\Csrf;
use Sentinel\Engagements\EngagementRepository;

$invalid = static fn (string $f): string => !empty($errors[$f]) ? ' is-invalid' : '';
$val = static fn (string $f): string => (string) ($values[$f] ?? '');
$clientId = (int) $client['id'];
?>
<p class="text-body-secondary"><?= e(__('Client: {name}. Times are in the client\'s timezone ({tz}).', ['name' => $client['name'], 'tz' => $client['timezone']])) ?></p>
<?php if ($errors !== []): ?><div class="alert alert-danger"><?= e(__('Please correct the highlighted fields.')) ?></div><?php endif; ?>
<form method="post" action="<?= e(url('/clients/' . $clientId . '/engagements')) ?>" enctype="multipart/form-data" novalidate>
<?= Csrf::field() ?>
<div class="row g-3">
    <div class="col-lg-6">
        <div class="card h-100">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Engagement and window')) ?></h2></div>
            <div class="card-body">
                <div class="mb-3">
                    <label for="name" class="form-label"><?= e(__('Name')) ?></label>
                    <input type="text" class="form-control<?= $invalid('name') ?>" id="name" name="name" value="<?= e($val('name')) ?>" maxlength="150" required>
                    <?php $field = 'name'; require __DIR__ . '/../partials/field_error.php'; ?>
                </div>
                <div class="row g-2 mb-1">
                    <div class="col-sm-6"><label for="window_start" class="form-label"><?= e(__('Testing may start')) ?></label>
                        <input type="datetime-local" class="form-control<?= $invalid('window') ?>" id="window_start" name="window_start" value="<?= e($val('window_start')) ?>" required></div>
                    <div class="col-sm-6"><label for="window_end" class="form-label"><?= e(__('Testing must end')) ?></label>
                        <input type="datetime-local" class="form-control<?= $invalid('window') ?>" id="window_end" name="window_end" value="<?= e($val('window_end')) ?>" required></div>
                </div>
                <div class="form-text mb-3"><?= e(__('At most {n} days. Nothing runs outside this window, before approval, or after a stop.', ['n' => EngagementRepository::MAX_DAYS])) ?></div>
                <?php $field = 'window'; require __DIR__ . '/../partials/field_error.php'; ?>
                <fieldset class="mb-3">
                    <legend class="form-label fs-6"><?= e(__('Tests allowed')) ?></legend>
                    <?php foreach ($testLabels as $key => $label): ?>
                    <div class="form-check"><input class="form-check-input" type="checkbox" name="tests[]" id="test-<?= e($key) ?>" value="<?= e($key) ?>" <?= in_array($key, (array) ($values['tests'] ?? []), true) ? 'checked' : '' ?>>
                        <label class="form-check-label" for="test-<?= e($key) ?>"><?= e($label) ?></label></div>
                    <?php endforeach; ?>
                    <div class="form-text"><?= e(__('No password guessing, no exploits, nothing that changes the systems tested.')) ?></div>
                    <?php $field = 'tests'; require __DIR__ . '/../partials/field_error.php'; ?>
                </fieldset>
                <fieldset class="mb-3">
                    <legend class="form-label fs-6"><?= e(__('How hard tests may push')) ?></legend>
                    <div class="form-check"><input class="form-check-input" type="radio" name="intensity" id="int-gentle" value="gentle" <?= $val('intensity') !== 'normal' ? 'checked' : '' ?>>
                        <label class="form-check-label" for="int-gentle"><?= e(__('Gentle: polite timing, as day-to-day scans (slow: hours per network)')) ?></label></div>
                    <div class="form-check"><input class="form-check-input" type="radio" name="intensity" id="int-normal" value="normal" <?= $val('intensity') === 'normal' ? 'checked' : '' ?>>
                        <label class="form-check-label" for="int-normal"><?= e(__('Normal: nmap normal timing (-T3), up to 200 packets a second; never aggressive (needed for all 65,535 ports)')) ?></label></div>
                    <?php $field = 'intensity'; require __DIR__ . '/../partials/field_error.php'; ?>
                </fieldset>
            </div>
        </div>
    </div>
    <div class="col-lg-6">
        <div class="card h-100">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('The client\'s signed authorisation')) ?></h2></div>
            <div class="card-body">
                <div class="mb-3">
                    <label for="document" class="form-label"><?= e(__('Signed authorisation (PDF, at most 10 MB)')) ?></label>
                    <input type="file" class="form-control<?= $invalid('document') ?>" id="document" name="document" accept="application/pdf,.pdf" required>
                    <div class="form-text"><?= e(__('It should name the targets, the tests, the window and who may run them. A template is in docs/authorisation-form.md.')) ?></div>
                    <?php $field = 'document'; require __DIR__ . '/../partials/field_error.php'; ?>
                </div>
                <div class="row g-2">
                    <div class="col-sm-6 mb-3"><label for="signer_name" class="form-label"><?= e(__('Signed by')) ?></label>
                        <input type="text" class="form-control<?= $invalid('signer_name') ?>" id="signer_name" name="signer_name" value="<?= e($val('signer_name')) ?>" maxlength="150" required>
                        <?php $field = 'signer_name'; require __DIR__ . '/../partials/field_error.php'; ?></div>
                    <div class="col-sm-6 mb-3"><label for="signer_role" class="form-label"><?= e(__('Their role')) ?></label>
                        <input type="text" class="form-control<?= $invalid('signer_role') ?>" id="signer_role" name="signer_role" value="<?= e($val('signer_role')) ?>" maxlength="150" required>
                        <?php $field = 'signer_role'; require __DIR__ . '/../partials/field_error.php'; ?></div>
                </div>
                <div class="mb-3"><label for="signed_on" class="form-label"><?= e(__('Signed on')) ?></label>
                    <input type="date" class="form-control<?= $invalid('signed_on') ?>" id="signed_on" name="signed_on" value="<?= e($val('signed_on')) ?>" required>
                    <?php $field = 'signed_on'; require __DIR__ . '/../partials/field_error.php'; ?></div>
                <?php if ($earlier !== []): ?>
                <div class="mb-3"><label for="retest_of" class="form-label"><?= e(__('This is a retest of (optional)')) ?></label>
                    <select class="form-select<?= $invalid('retest_of') ?>" id="retest_of" name="retest_of"><option value=""><?= e(__('No: a new test')) ?></option>
                        <?php foreach ($earlier as $g): ?><option value="<?= (int) $g['id'] ?>" <?= $val('retest_of') === (string) $g['id'] ? 'selected' : '' ?>><?= e('#' . (int) $g['id'] . ' ' . $g['name']) ?></option><?php endforeach; ?></select>
                    <div class="form-text"><?= e(__('Its report becomes a retest letter: each earlier finding marked fixed, still open or not retested.')) ?></div>
                    <?php $field = 'retest_of'; require __DIR__ . '/../partials/field_error.php'; ?></div>
                <?php endif; ?>
                <div class="mb-3"><label for="notes" class="form-label"><?= e(__('Notes (optional)')) ?></label>
                    <textarea class="form-control<?= $invalid('notes') ?>" id="notes" name="notes" rows="3" maxlength="5000"><?= e($val('notes')) ?></textarea>
                    <?php $field = 'notes'; require __DIR__ . '/../partials/field_error.php'; ?></div>
            </div>
        </div>
    </div>
    <div class="col-12">
        <div class="card">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Scope')) ?></h2></div>
            <div class="card-body">
                <p class="small text-body-secondary"><?= e(__('Every target must already be in this client\'s authorised scope, for the whole window. One per line; # starts a comment.')) ?></p>
                <div class="mb-3">
                    <label for="external" class="form-label"><?= e(__('External targets (public IPs, ranges, domains)')) ?></label>
                    <textarea class="form-control font-monospace<?= $invalid('external') ?>" id="external" name="external" rows="4" spellcheck="false"><?= e($val('external')) ?></textarea>
                    <div class="form-text"><?= e(__('Authorised now: {list}', ['list' => $scope === [] ? __('nothing') : implode(', ', array_slice(array_map(static fn (array $s): string => (string) $s['value'], $scope), 0, 30))])) ?></div>
                    <?php $field = 'external'; require __DIR__ . '/../partials/field_error.php'; ?>
                </div>
                <?php foreach ($sites as $s): $sid = (int) $s['site']['id']; $fname = 'internal_' . $sid; ?>
                <div class="mb-3">
                    <label for="<?= e($fname) ?>" class="form-label"><?= e(__('Internal ranges at site {s} (through its agent)', ['s' => $s['site']['name']])) ?></label>
                    <textarea class="form-control font-monospace<?= $invalid($fname) ?>" id="<?= e($fname) ?>" name="<?= e($fname) ?>" rows="2" spellcheck="false"><?= e((string) ($values['internal'][$sid] ?? '')) ?></textarea>
                    <div class="form-text"><?= e($s['ranges'] === [] ? __('This site has no active internal authorisation.') : __('Authorised: {list} (until {d}).', ['list' => implode(', ', $s['ranges']), 'd' => $s['until']])) ?></div>
                    <?php $field = $fname; require __DIR__ . '/../partials/field_error.php'; ?>
                </div>
                <?php endforeach; ?>
                <div class="mb-3">
                    <label for="exclusions" class="form-label"><?= e(__('Exclusions: never touch these (optional)')) ?></label>
                    <textarea class="form-control font-monospace<?= $invalid('exclusions') ?>" id="exclusions" name="exclusions" rows="2" spellcheck="false"><?= e($val('exclusions')) ?></textarea>
                    <div class="form-text"><?= e(__('IP addresses or ranges (not names) of fragile or third-party systems inside the ranges above, e.g. a phone system or a medical device.')) ?></div>
                    <?php $field = 'exclusions'; require __DIR__ . '/../partials/field_error.php'; ?>
                </div>
                <div class="form-check mb-3">
                    <input class="form-check-input<?= $invalid('confirm') ?>" type="checkbox" id="confirm" name="confirm" value="1" <?= $val('confirm') === '1' ? 'checked' : '' ?>>
                    <label class="form-check-label" for="confirm"><?= e(__('The client signed the attached authorisation for these targets, tests and window.')) ?></label>
                    <?php $field = 'confirm'; require __DIR__ . '/../partials/field_error.php'; ?>
                </div>
                <button class="btn btn-primary" type="submit"><?= e(__('Create engagement (needs another admin\'s approval)')) ?></button>
                <a class="btn btn-outline-secondary" href="<?= e(url('/clients/' . $clientId . '/engagements')) ?>"><?= e(__('Cancel')) ?></a>
            </div>
        </div>
    </div>
</div>
</form>

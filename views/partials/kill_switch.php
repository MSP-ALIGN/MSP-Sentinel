<?php
/**
 * Global kill switch banner and buttons.
 * Expects: $globallyPaused (bool), $currentUser (public fields).
 * Technicians and admins see "Pause all scanning"; only admins see "Resume".
 */
use Sentinel\Core\Csrf;

// The kill switch reaches every client (1.42.1): only for users who see every client.
$everyClient = ($currentUser['client_ids'] ?? null) === null;
$canPause = can('scanning.pause') && $everyClient;
$canResume = can('scanning.resume') && $everyClient;
?>
<?php if ($globallyPaused): ?>
<div class="alert alert-danger d-flex align-items-center flex-wrap gap-2" role="status">
    <i class="bi bi-pause-circle-fill" aria-hidden="true"></i>
    <strong><?= e(__('All scanning is paused.')) ?></strong>
    <span><?= e(__('Nothing will be scanned until an admin resumes it.')) ?></span>
    <?php if ($canResume): ?>
    <form method="post" action="<?= e(url('/scanning/resume')) ?>" class="ms-auto" data-confirm="<?= e(__('Resume scanning for all clients?')) ?>">
        <?= Csrf::field() ?>
        <button type="submit" class="btn btn-sm btn-light"><i class="bi bi-play-fill me-1" aria-hidden="true"></i><?= e(__('Resume scanning')) ?></button>
    </form>
    <?php endif; ?>
</div>
<?php elseif ($canPause): ?>
<form method="post" action="<?= e(url('/scanning/pause')) ?>" class="d-inline" data-confirm="<?= e(__('Pause ALL scanning for every client now?')) ?>">
    <?= Csrf::field() ?>
    <button type="submit" class="btn btn-sm btn-outline-danger"><i class="bi bi-pause-fill me-1" aria-hidden="true"></i><?= e(__('Pause all scanning')) ?></button>
</form>
<?php endif; ?>

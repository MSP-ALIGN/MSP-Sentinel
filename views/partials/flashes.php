<?php
/**
 * Flash messages and a single error message.
 * Expects: $flashes (list of type/message), optional $error (string). All values escaped.
 */
$allowedTypes = ['success', 'info', 'warning', 'danger'];
foreach (($flashes ?? []) as $flash):
    $type = in_array($flash['type'] ?? '', $allowedTypes, true) ? $flash['type'] : 'info';
?>
<div class="alert alert-<?= e($type) ?>" role="alert"><?= e($flash['message'] ?? '') ?></div>
<?php endforeach; ?>
<?php if (!empty($error)): ?>
<div class="alert alert-danger" role="alert"><i class="bi bi-exclamation-triangle-fill me-1" aria-hidden="true"></i><?= e($error) ?></div>
<?php endif; ?>

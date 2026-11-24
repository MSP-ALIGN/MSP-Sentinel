<?php
/** Error page. Expects: $status (int), $title, $message (user-safe text). */
?>
<div class="text-center py-3">
    <div class="display-6 text-body-secondary"><?= e($status) ?></div>
    <h2 class="h4 mt-2"><?= e($title) ?></h2>
    <p class="text-body-secondary"><?= e($message) ?></p>
    <a href="<?= e(url('/')) ?>" class="btn btn-outline-primary btn-sm"><?= e(__('Go to the start page')) ?></a>
</div>

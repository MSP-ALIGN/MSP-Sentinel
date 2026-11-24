<?php
/** One-time display of new recovery codes. Expects: $codes (list of strings). */
?>
<div class="row">
    <div class="col-lg-7">
        <div class="card card-outline card-warning">
            <div class="card-body">
                <p><strong><?= e(__('Save these recovery codes somewhere safe, such as your password manager.')) ?></strong></p>
                <p><?= e(__('Each code signs you in once if you lose your authenticator app. They will not be shown again.')) ?></p>
                <ul class="list-unstyled recovery-codes row g-2" data-testid="recovery-codes">
                    <?php foreach ($codes as $code): ?>
                    <li class="col-6"><code class="d-block p-2 bg-body-tertiary rounded text-center"><?= e($code) ?></code></li>
                    <?php endforeach; ?>
                </ul>
                <a href="<?= e(url('/')) ?>" class="btn btn-primary"><?= e(__('I have saved my codes')) ?></a>
            </div>
        </div>
    </div>
</div>

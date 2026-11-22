<?php
/**
 * A new one-time enrolment code (shown once; the page is not cached) with install steps.
 * Expects: $client, $site, $code, $serverUrl.
 */
?>
<div class="card">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Enrol an agent: {client}, {site}', ['client' => $client['name'], 'site' => $site['name']])) ?></h2></div>
    <div class="card-body">
        <div class="alert alert-warning"><i class="bi bi-exclamation-triangle me-1" aria-hidden="true"></i><?= e(__('This code is shown only once. It works once, within 24 hours, for this site only.')) ?></div>
        <p class="mb-1"><?= e(__('Enrolment code')) ?></p>
        <p class="h3 font-monospace mb-4" id="enrol-code"><?= e($code) ?></p>
        <h3 class="h6"><?= e(__('Install on the appliance (Ubuntu 24.04 or Debian 12, mini-PC or VM on the internal network)')) ?></h3>
        <ol class="small">
            <li><?= e(__('Copy the Sentinel release archive (the same file you installed Sentinel from) to the appliance and unpack it.')) ?></li>
            <li><?= e(__('Run, as root, in the unpacked folder:')) ?>
                <pre class="bg-body-tertiary p-2 mt-1 mb-1"><code>sudo ./install/agent-install.sh --server <?= e($serverUrl !== '' ? $serverUrl : 'https://sentinel.example') ?> --code <?= e($code) ?></code></pre>
                <?php if ($serverUrl === ''): ?><div class="text-warning"><?= e(__('Set app.public_url in the config so this command shows your address.')) ?></div><?php endif; ?></li>
            <li><?= e(__('The agent appears on the client page within a minute. It only connects out to Sentinel over HTTPS; no firewall rule is needed at the site.')) ?></li>
        </ol>
        <a class="btn btn-outline-secondary" href="<?= e(url('/clients/' . (int) $client['id'] . '/agents')) ?>"><?= e(__('Back to the client')) ?></a>
    </div>
</div>

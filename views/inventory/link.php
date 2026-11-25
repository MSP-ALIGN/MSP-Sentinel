<?php
/**
 * Link a client to an organisation in an inventory source (admins).
 * Expects: $client, $sourceName, $sourceLabel, $orgs (from the source), $error, $suggested (org ID|null), $link (current|null).
 * Organisation names come from the source (untrusted) and are escaped.
 */
use Sentinel\Core\Csrf;
?>
<div class="card">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Link {client} to a {source} organization', ['client' => $client['name'], 'source' => $sourceLabel])) ?></h2></div>
    <form method="post" action="<?= e(url('/clients/' . (int) $client['id'] . '/inventory/link')) ?>">
    <div class="card-body">
        <?= Csrf::field() ?><input type="hidden" name="source" value="<?= e($sourceName) ?>">
        <?php if ($error !== ''): ?><div class="alert alert-danger"><?= e($error) ?></div><?php endif; ?>
        <p class="small text-body-secondary"><?= e(__('Sentinel then reads this organization\'s devices, installed software and missing updates from {source} every 6 hours (read-only). Each organization can belong to only one client.', ['source' => $sourceLabel])) ?></p>
        <?php if ($link !== null): ?><p class="small"><?= e(__('Currently linked to {org}. Choosing another organization replaces the link.', ['org' => $link['org_name']])) ?></p><?php endif; ?>
        <?php if ($suggested !== null): ?><p class="small"><i class="bi bi-lightbulb me-1" aria-hidden="true"></i><?= e(__('Suggested by name. Check it before you link.')) ?></p><?php endif; ?>
        <label class="form-label" for="org_id"><?= e(__('Organization')) ?></label>
        <select class="form-select" id="org_id" name="org_id" required>
            <option value=""><?= e(__('Choose…')) ?></option>
            <?php foreach ($orgs as $o): ?><option value="<?= e($o['id']) ?>" <?= $suggested === $o['id'] ? 'selected' : '' ?>><?= e($o['name']) ?><?= $suggested === $o['id'] ? ' ' . e(__('(suggested)')) : '' ?></option><?php endforeach; ?>
        </select>
    </div>
    <div class="card-footer d-flex gap-2"><button type="submit" class="btn btn-primary" <?= $orgs === [] ? 'disabled' : '' ?>><?= e(__('Link')) ?></button>
        <a class="btn btn-outline-secondary" href="<?= e(url('/clients/' . (int) $client['id'] . '/devices')) ?>"><?= e(__('Cancel')) ?></a></div>
    </form>
</div>

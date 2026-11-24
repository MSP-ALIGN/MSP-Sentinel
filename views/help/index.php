<?php
/** Help and "What's new". Expects: $entries = ['topics' => [...], 'releases' => [...]] (trusted text, still escaped). */
?>
<div class="row g-3">
    <div class="col-lg-7" id="help-topics">
        <div class="d-flex align-items-center gap-2 mb-3"><label class="visually-hidden" for="help-filter"><?= e(__('Search the help')) ?></label>
            <input class="form-control" type="search" id="help-filter" maxlength="100" data-filter-list="#help-topics" data-filter-count="#help-filter-count" data-filter-from-url placeholder="<?= e(__('Search the help…')) ?>">
            <span class="small text-body-secondary text-nowrap" id="help-filter-count" aria-live="polite"></span></div>
        <?php foreach (($entries['topics'] ?? []) as $topic): ?>
        <div data-filter-item id="<?= e(trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower((string) $topic['title'])), '-')) ?>" class="card mb-3">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e($topic['title']) ?></h2></div>
            <div class="card-body">
                <?php foreach ($topic['paragraphs'] as $paragraph): ?>
                <p><?= e($paragraph) ?></p>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endforeach; ?>
    </div>
    <div class="col-lg-5">
        <div class="card">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__("What's new")) ?></h2></div>
            <div class="card-body">
                <?php foreach (($entries['releases'] ?? []) as $release): ?>
                <h3 class="h6"><?= e($release['version']) ?> <span class="text-body-secondary small"><?= e($release['date']) ?></span></h3>
                <ul>
                    <?php foreach ($release['items'] as $item): ?>
                    <li><?= e($item) ?></li>
                    <?php endforeach; ?>
                </ul>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
</div>

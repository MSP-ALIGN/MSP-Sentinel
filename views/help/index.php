<?php
/**
 * Help (1.34: task-based). Expects: $entries = ['topics' => [...], 'releases' => [...]] (trusted text, still escaped).
 *
 * A table of contents, then the topics grouped by their 'section' (start, tasks, admin, reference; anything else
 * goes under Reference), each card with an id anchor (the slug of its title, e.g. /help#searching-and-filtering).
 * The filter box filters the cards of every section; a section whose cards all are hidden is hidden too
 * (data-filter-group, sentinel.js). The release history is last, folded away. Every value is escaped with e().
 */
$sections = [
    'start' => ['id' => 'start-here', 'title' => __('Start here'), 'icon' => 'bi-flag'],
    'tasks' => ['id' => 'everyday-tasks', 'title' => __('Everyday tasks'), 'icon' => 'bi-list-check'],
    'admin' => ['id' => 'setting-up', 'title' => __('Setting up and running Sentinel (admins)'), 'icon' => 'bi-gear'],
    'reference' => ['id' => 'reference', 'title' => __('Reference'), 'icon' => 'bi-book'],
];
$grouped = array_fill_keys(array_keys($sections), []);
foreach (($entries['topics'] ?? []) as $topic) {
    $key = isset($sections[$topic['section'] ?? '']) ? $topic['section'] : 'reference';
    $grouped[$key][] = $topic;
}
/** The anchor for a topic title: lower case, runs of other characters as "-" (the result is escaped where used). */
$slug = static fn (string $title): string => trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower($title)), '-');
$releases = $entries['releases'] ?? [];
?>
<div class="row g-3">
    <div class="col-xl-9">
        <nav class="card mb-3" aria-labelledby="help-toc-title">
            <div class="card-header"><h2 class="card-title h5 mb-0" id="help-toc-title"><?= e(__('Contents')) ?></h2></div>
            <div class="card-body">
                <ul class="list-unstyled mb-0" id="help-toc">
                    <?php foreach ($sections as $key => $s): if ($grouped[$key] === []) { continue; } ?>
                    <li class="mb-2"><i class="bi <?= e($s['icon']) ?> me-2" aria-hidden="true"></i><a href="#<?= e($s['id']) ?>"><?= e($s['title']) ?></a>
                        <div class="small ms-4"><?php foreach ($grouped[$key] as $i => $t): ?><?= $i > 0 ? ' · ' : '' ?><a class="link-secondary" href="#<?= e($slug((string) $t['title'])) ?>"><?= e($t['title']) ?></a><?php endforeach; ?></div></li>
                    <?php endforeach; ?>
                    <?php if ($releases !== []): ?>
                    <li><i class="bi bi-clock-history me-2" aria-hidden="true"></i><a href="#release-history"><?= e(__('Release history')) ?></a></li>
                    <?php endif; ?>
                </ul>
            </div>
        </nav>

        <div class="d-flex align-items-center gap-2 mb-3"><label class="visually-hidden" for="help-filter"><?= e(__('Search the help')) ?></label>
            <input class="form-control" type="search" id="help-filter" maxlength="100" data-filter-list="#help-topics" data-filter-count="#help-filter-count" data-filter-from-url placeholder="<?= e(__('Search the help…')) ?>">
            <span class="small text-body-secondary text-nowrap" id="help-filter-count" aria-live="polite"></span></div>

        <div id="help-topics">
            <?php foreach ($sections as $key => $s): if ($grouped[$key] === []) { continue; } ?>
            <section data-filter-group id="<?= e($s['id']) ?>" class="mb-4" aria-labelledby="<?= e($s['id']) ?>-title">
                <h2 class="h4 mb-3" id="<?= e($s['id']) ?>-title"><i class="bi <?= e($s['icon']) ?> me-2" aria-hidden="true"></i><?= e($s['title']) ?></h2>
                <?php foreach ($grouped[$key] as $topic): ?>
                <div data-filter-item id="<?= e($slug((string) $topic['title'])) ?>" class="card mb-3">
                    <?php // Anchors of earlier titles (1.51.1), so old links and bookmarks still land on the topic. ?>
                    <?php foreach ((array) ($topic['old_anchors'] ?? []) as $old): ?><span id="<?= e($slug((string) $old)) ?>"></span><?php endforeach; ?>
                    <div class="card-header"><h3 class="card-title h5 mb-0"><?= e($topic['title']) ?></h3></div>
                    <div class="card-body">
                        <?php foreach ($topic['paragraphs'] as $paragraph): ?>
                        <p><?= e($paragraph) ?></p>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endforeach; ?>
            </section>
            <?php endforeach; ?>
        </div>

        <?php if ($releases !== []): ?>
        <details class="card mb-3" id="release-history">
            <summary class="card-header h5 mb-0"><?= e(__('Release history')) ?> <span class="text-body-secondary small"><?= e(__('newest first')) ?></span></summary>
            <div class="card-body">
                <?php foreach ($releases as $release): ?>
                <h3 class="h6"><?= e($release['version']) ?> <span class="text-body-secondary small"><?= e($release['date']) ?></span></h3>
                <ul>
                    <?php foreach ($release['items'] as $item): ?>
                    <li><?= e($item) ?></li>
                    <?php endforeach; ?>
                </ul>
                <?php endforeach; ?>
            </div>
        </details>
        <?php endif; ?>
    </div>
</div>

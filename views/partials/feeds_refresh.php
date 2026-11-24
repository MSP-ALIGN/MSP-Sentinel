<?php
/**
 * Vulnerability data refresh status and the Refresh now button (admins). Expects: $feedsRefresh
 * (FeedSchedule::status()). Every value is escaped.
 */
use Sentinel\Core\Csrf;

$fr = $feedsRefresh;
?>
<div class="d-flex flex-wrap align-items-center gap-2 mt-3" id="feeds-refresh">
    <?php if ($fr['running']): ?>
    <span class="badge text-bg-warning"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i><?= e(__('Refreshing')) ?></span>
    <span class="small"><?= e(__('Started {t}. A first download without an NVD API key can take a while.', ['t' => when($fr['started'])])) ?></span>
    <?php elseif ($fr['requested']): ?>
    <span class="badge text-bg-info"><?= e(__('Waiting')) ?></span>
    <span class="small"><?= e(__('Refresh requested: it starts within 5 minutes.')) ?></span>
    <?php else: ?>
    <form method="post" action="<?= e(url('/admin/feeds/refresh')) ?>"><?= Csrf::field() ?>
        <button type="submit" class="btn btn-outline-primary btn-sm"><i class="bi bi-arrow-clockwise me-1" aria-hidden="true"></i><?= e(__('Refresh now')) ?></button></form>
    <span class="small text-body-secondary"><?= e(match (true) {
        $fr['finished'] !== '' && !$fr['ok'] => __('The last refresh ({t}) had a problem (see the feeds above); it tries again within an hour.', ['t' => when($fr['finished'])]),
        $fr['finished'] !== '' => __('Last refresh finished {t}.', ['t' => when($fr['finished'])]),
        $fr['started'] !== '' => __('The last refresh started {t} and did not finish; the next one starts within an hour.', ['t' => when($fr['started'])]),
        default => __('Not refreshed yet.'),
    }) ?></span>
    <?php endif; ?>
</div>
<p class="mb-0 mt-2 small text-body-secondary"><?= e(__('Refreshed automatically about once a day (and within minutes of installing; after a problem, again within an hour). Nothing about your clients is sent to the feeds.')) ?></p>

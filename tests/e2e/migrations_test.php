<?php

declare(strict_types=1);

/**
 * Migration idempotency, second layer: each migration file must be safe to
 * run again even if schema_migrations forgot it (e.g. a crash after the DDL
 * but before the bookkeeping insert).
 */

use Sentinel\Migrations\Migrator;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'every migration can run again on an up-to-date database' => function (TestContext $ctx): void {
        $before = (int) $ctx->db->query('SELECT COUNT(*) FROM users')->fetchColumn();
        $ctx->db->exec('DELETE FROM schema_migrations');
        $applied = (new Migrator($ctx->db, $ctx->root . '/migrations'))->migrate();
        Assert::true(count($applied) >= 1, 'migrations re-applied');
        Assert::same($before, (int) $ctx->db->query('SELECT COUNT(*) FROM users')->fetchColumn(), 'data untouched');
        Assert::same([], (new Migrator($ctx->db, $ctx->root . '/migrations'))->migrate(), 'third run is a no-op');
    },
];

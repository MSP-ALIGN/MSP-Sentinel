<?php

declare(strict_types=1);

namespace Sentinel\Migrations;

use PDO;

/**
 * Runs database migrations from the migrations/ directory, in filename order.
 *
 * Each migration file returns ['description' => string, 'up' => callable(PDO, Migrator)].
 *
 * Idempotency, in two layers:
 * 1. Applied migrations are recorded in schema_migrations and skipped next time.
 * 2. Each migration ALSO checks before it changes anything (tableExists,
 *    columnExists, indexExists), so it is safe to run again after a partial
 *    failure. MariaDB DDL commits implicitly, so a half-applied migration
 *    can't be rolled back.
 *
 * Security assumptions:
 * - Migration files are trusted code shipped with the release.
 * - Identifiers passed to the helpers are written in code, never user input.
 *   They are still checked against a strict pattern.
 * - A named database lock stops two migration runs (e.g. two containers
 *   starting together) from overlapping.
 */
final class Migrator
{
    private const LOCK_NAME = 'msp_sentinel_migrate';

    /** Migrations are read from $directory (trusted, shipped with the app). */
    public function __construct(private readonly PDO $db, private readonly string $directory)
    {
    }

    /**
     * Apply all pending migrations.
     *
     * @param callable(string):void|null $log Receives one line per migration.
     * @return list<string> IDs of migrations applied in this run.
     */
    public function migrate(?callable $log = null): array
    {
        $log ??= static function (string $line): void {
        };
        $got = (int) $this->db->query("SELECT GET_LOCK('" . self::LOCK_NAME . "', 30)")->fetchColumn();
        if ($got !== 1) {
            throw new \RuntimeException('Another migration run holds the lock. Try again shortly.');
        }
        try {
            $this->db->exec(
                'CREATE TABLE IF NOT EXISTS schema_migrations (
                    id VARCHAR(100) NOT NULL PRIMARY KEY,
                    description VARCHAR(255) NOT NULL,
                    applied_at DATETIME NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
            );
            $applied = $this->db->query('SELECT id FROM schema_migrations')->fetchAll(PDO::FETCH_COLUMN);
            $done = [];
            foreach ($this->files() as $id => $file) {
                if (in_array($id, $applied, true)) {
                    continue;
                }
                $migration = require $file;
                if (!is_array($migration) || !isset($migration['up']) || !is_callable($migration['up'])) {
                    throw new \RuntimeException("Migration {$id} is malformed.");
                }
                $log("Applying {$id}: " . ($migration['description'] ?? ''));
                ($migration['up'])($this->db, $this);
                $stmt = $this->db->prepare('INSERT IGNORE INTO schema_migrations (id, description, applied_at) VALUES (:id, :d, UTC_TIMESTAMP())');
                $stmt->execute(['id' => $id, 'd' => mb_substr((string) ($migration['description'] ?? ''), 0, 255)]);
                $done[] = $id;
            }
            return $done;
        } finally {
            $this->db->query("SELECT RELEASE_LOCK('" . self::LOCK_NAME . "')");
        }
    }

    /** @return array<string,string> migration id => file path, sorted. */
    private function files(): array
    {
        $files = [];
        foreach (glob($this->directory . '/*.php') ?: [] as $file) {
            $id = basename($file, '.php');
            if (preg_match('/^\d{4}_[a-z0-9_]+$/', $id)) {
                $files[$id] = $file;
            }
        }
        ksort($files, SORT_STRING);
        return $files;
    }

    /** True if the table exists in the current database. */
    public function tableExists(string $table): bool
    {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t');
        $stmt->execute(['t' => self::ident($table)]);
        return (int) $stmt->fetchColumn() > 0;
    }

    /** True if the column exists on the table. */
    public function columnExists(string $table, string $column): bool
    {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND COLUMN_NAME = :c');
        $stmt->execute(['t' => self::ident($table), 'c' => self::ident($column)]);
        return (int) $stmt->fetchColumn() > 0;
    }

    /** True if an index with this name exists on the table. */
    public function indexExists(string $table, string $index): bool
    {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND INDEX_NAME = :i');
        $stmt->execute(['t' => self::ident($table), 'i' => self::ident($index)]);
        return (int) $stmt->fetchColumn() > 0;
    }

    /** Add a column only if it is missing. $definition is trusted SQL written in a migration. */
    public function addColumnIfMissing(string $table, string $column, string $definition): void
    {
        if (!$this->columnExists($table, $column)) {
            $this->db->exec(sprintf('ALTER TABLE `%s` ADD COLUMN `%s` %s', self::ident($table), self::ident($column), $definition));
        }
    }

    /** Guard for identifiers: letters, digits and underscores only. */
    private static function ident(string $name): string
    {
        if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', $name)) {
            throw new \InvalidArgumentException('Invalid identifier.');
        }
        return $name;
    }
}

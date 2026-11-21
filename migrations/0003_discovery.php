<?php

declare(strict_types=1);

/**
 * Migration 0003: target discovery (suggestions and discovery runs).
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS. Safe to run twice.
 *
 * Security notes:
 * - target_suggestions never grants anything: a suggestion is only a hint
 *   until an admin records a new authorisation that includes it.
 * - Values are canonical (validated) hostnames or IPs. The unique key stops
 *   the same suggestion from appearing twice for a client.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Target discovery: suggestions and discovery runs',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';

        $db->exec("CREATE TABLE IF NOT EXISTS target_suggestions (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            kind ENUM('hostname','ip') NOT NULL,
            value VARCHAR(260) NOT NULL,
            source VARCHAR(32) NOT NULL,
            detail VARCHAR(500) NOT NULL DEFAULT '',
            third_party_hint TINYINT(1) NOT NULL DEFAULT 0,
            status ENUM('pending','accepted','dismissed') NOT NULL DEFAULT 'pending',
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            decided_by INT UNSIGNED NULL,
            decided_at DATETIME NULL,
            UNIQUE KEY uq_suggestion (client_id, value),
            KEY idx_suggestion_status (client_id, status),
            CONSTRAINT fk_suggestion_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS discovery_runs (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            trigger_type ENUM('manual','scheduled') NOT NULL,
            triggered_by INT UNSIGNED NULL,
            status ENUM('running','ok','partial','failed') NOT NULL DEFAULT 'running',
            started_at DATETIME NOT NULL,
            finished_at DATETIME NULL,
            summary TEXT NULL,
            KEY idx_runs_client (client_id, id),
            CONSTRAINT fk_runs_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) {$opts}");
    },
];

<?php

declare(strict_types=1);

/**
 * Migration 0008: alerts (in-app notifications, an email/webhook outbox, user email preferences).
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS and addColumnIfMissing. Safe to run twice.
 *
 * Security notes:
 * - The outbox stores the message to send (subject, plain-text body, recipient)
 *   but never SMTP credentials or webhook URLs. Those stay encrypted in settings.
 * - Notification text is built from finding titles (scan data, untrusted) and is escaped on output.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Alerts: notifications, outbox, user alert preferences',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';

        $m->addColumnIfMissing('users', 'alert_email', "ENUM('none','immediate','digest','both') NOT NULL DEFAULT 'immediate'");

        $db->exec("CREATE TABLE IF NOT EXISTS notifications (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id INT UNSIGNED NOT NULL,
            kind VARCHAR(30) NOT NULL,
            severity ENUM('fail','warn','info') NOT NULL DEFAULT 'info',
            title VARCHAR(300) NOT NULL,
            body VARCHAR(2000) NOT NULL DEFAULT '',
            link VARCHAR(300) NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL,
            read_at DATETIME NULL,
            KEY idx_notif_user (user_id, read_at, id),
            CONSTRAINT fk_notif_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS deliveries (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            channel ENUM('email','webhook') NOT NULL,
            recipient VARCHAR(500) NOT NULL DEFAULT '',
            subject VARCHAR(300) NOT NULL DEFAULT '',
            body MEDIUMTEXT NOT NULL,
            status ENUM('pending','sent','failed') NOT NULL DEFAULT 'pending',
            attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
            next_attempt_at DATETIME NOT NULL,
            last_error VARCHAR(300) NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL,
            sent_at DATETIME NULL,
            KEY idx_deliveries_due (status, next_attempt_at)
        ) {$opts}");
    },
];

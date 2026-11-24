<?php

declare(strict_types=1);

namespace Sentinel\Core;

use PDO;

/**
 * Creates the PDO connection to MariaDB.
 *
 * Security assumptions:
 * - All queries in the app use prepared statements with bound parameters.
 *   Real (not emulated) prepares are on, so values never get spliced into
 *   SQL text.
 * - Strict SQL mode is on, so bad data fails loudly instead of being
 *   silently truncated.
 */
final class Database
{
    /**
     * Open a connection using the "db" section of the configuration.
     *
     * @throws \PDOException on connection failure. Callers must not show the
     *         message to users, because it can include the host name.
     */
    public static function connect(Config $config): PDO
    {
        $host = (string) $config->get('db.host');
        $port = (int) $config->get('db.port', 3306);
        $name = (string) $config->get('db.name');
        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $host, $port, $name);

        $pdo = new PDO($dsn, (string) $config->get('db.user'), (string) $config->get('db.pass', ''), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_STRINGIFY_FETCHES => false,
        ]);
        $pdo->exec("SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'");
        // Store and compare all timestamps in UTC. They are converted for display only.
        $pdo->exec("SET time_zone = '+00:00'");
        return $pdo;
    }
}

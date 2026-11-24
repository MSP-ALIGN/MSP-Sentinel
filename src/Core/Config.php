<?php

declare(strict_types=1);

namespace Sentinel\Core;

/**
 * Read-only application configuration.
 *
 * Loaded from a PHP file that returns an array (config/config.php by default,
 * or the path in the SENTINEL_CONFIG environment variable). The file lives
 * outside the web root.
 *
 * Security assumptions:
 * - The config file is trusted and writable only by the server administrator.
 * - It holds secrets (database password, app key). Values from it are never
 *   printed, logged or sent to the browser.
 */
final class Config
{
    /** @param array<string,mixed> $data */
    private function __construct(private readonly array $data)
    {
    }

    /**
     * Load and validate the configuration file.
     *
     * @throws \RuntimeException if the file is missing or invalid. The message
     *         never contains secret values.
     */
    public static function load(?string $path = null): self
    {
        $path ??= getenv('SENTINEL_CONFIG') ?: SENTINEL_ROOT . '/config/config.php';
        if (!is_file($path) || !is_readable($path)) {
            throw new \RuntimeException('Configuration file not found. Copy config/config.example.php to config/config.php.');
        }
        $data = require $path;
        if (!is_array($data)) {
            throw new \RuntimeException('Configuration file must return an array.');
        }
        return self::fromArray($data);
    }

    /**
     * Build from an array (used by load() and by tests).
     *
     * @param array<string,mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $config = new self($data);
        $config->validate();
        return $config;
    }

    /**
     * Get a value by dot path, e.g. "db.host".
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $value = $this->data;
        foreach (explode('.', $key) as $part) {
            if (!is_array($value) || !array_key_exists($part, $value)) {
                return $default;
            }
            $value = $value[$part];
        }
        return $value;
    }

    /**
     * Decoded 32-byte application key, used to encrypt secrets at rest.
     */
    public function appKey(): string
    {
        return base64_decode((string) $this->get('app_key'), true);
    }

    /**
     * Fail early on settings the app can't safely run without.
     */
    private function validate(): void
    {
        $key = base64_decode((string) $this->get('app_key', ''), true);
        if ($key === false || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new \RuntimeException('app_key must be 32 random bytes, base64-encoded. Generate one with: php bin/generate-key.php');
        }
        foreach (['db.host', 'db.name', 'db.user'] as $required) {
            if ((string) $this->get($required, '') === '') {
                throw new \RuntimeException("Missing configuration value: {$required}");
            }
        }
        $basePath = (string) $this->get('app.base_path', '');
        if ($basePath !== '' && !preg_match('#^(/[A-Za-z0-9._~-]+)+$#', $basePath)) {
            throw new \RuntimeException('app.base_path must look like "/sentinel" (no trailing slash), or be empty.');
        }
    }
}

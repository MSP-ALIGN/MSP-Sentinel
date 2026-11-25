<?php

declare(strict_types=1);

namespace Sentinel\Inventory;

/**
 * The kinds of inventory source Sentinel can connect to (1.52). Adding an RMM: write its InventorySource and
 * SourceType, add the type here, add its settings to Settings::DEFAULTS (and secrets to Settings::SECRETS), and give it
 * a mock server and an end-to-end test. Everything else (Integrations page, save and test, links, syncs) uses this list.
 *
 * The list is written in code, never configured, so names are trusted: they are used in routes and settings keys.
 */
final class Sources
{
    /** Settings every source has ("<name>_enabled", ...): no field may use these keys. */
    public const RESERVED = ['enabled', 'tested_at', 'test_result'];

    /** @return array<string,SourceType> by name */
    public static function types(): array
    {
        $types = [];
        foreach ([new NinjaOneType()] as $type) {
            // Field keys must not take the place of the keys every source has (1.52.1): a mistake here would be caught at once.
            foreach ($type->fields() as $f) {
                if (in_array($f['key'], self::RESERVED, true) || preg_match('/^[a-z][a-z0-9_]*$/', $f['key']) !== 1) {
                    throw new \LogicException('Field key not allowed: ' . $type->name() . '.' . $f['key']);
                }
            }
            $types[$type->name()] = $type;
        }
        return $types;
    }

    /** One kind by name, or null for a name that isn't registered (e.g. untrusted input). */
    public static function type(string $name): ?SourceType
    {
        return self::types()[$name] ?? null;
    }
}

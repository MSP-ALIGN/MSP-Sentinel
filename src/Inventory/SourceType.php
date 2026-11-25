<?php

declare(strict_types=1);

namespace Sentinel\Inventory;

use Sentinel\Core\Settings;

/**
 * One kind of inventory source (an RMM such as NinjaOne), as Sentinel needs to know it before it is connected (1.52):
 * its name and label, the settings an admin fills in on the Integrations page, how they are checked, and how to build
 * the connector from them. Adding an RMM means one SourceType and one InventorySource, registered in Sources.
 *
 * Field keys are lower case letters, digits and "_", never enabled, tested_at or test_result (Sources checks).
 * Settings are stored under "<name>_<field key>" (secret fields encrypted: they must be listed in Settings::SECRETS
 * and in Settings::DEFAULTS), plus "<name>_enabled", "<name>_tested_at" and "<name>_test_result".
 *
 * Untrusted: every value passed to normalise() and validate() comes from the admin's form. validate() is the only
 * gate before a value is stored, so it must allow only what the connector can safely use (for example a host name
 * that belongs to the vendor, so a secret is never sent anywhere else).
 */
interface SourceType
{
    /** Short machine name (letters and digits), also the InventorySource name, the settings prefix and the URL part. */
    public function name(): string;

    /** Name for people (e.g. "NinjaOne"). */
    public function label(): string;

    /**
     * The settings fields, in form order. Each: key (letters, digits, "_"), label, secret (bool: stored encrypted, never
     * shown again), maxlength, and optionally placeholder, help, suggestions (list<string>) and account (bool: changing it
     * while clients are linked may point the links at another account, so the admin is warned).
     *
     * @return list<array{key:string,label:string,secret:bool,maxlength:int,placeholder?:string,help?:string,suggestions?:list<string>,account?:bool}>
     */
    public function fields(): array;

    /** Tidies one field value before it is checked (e.g. a pasted URL becomes its host name). */
    public function normalise(string $key, string $value): string;

    /** Why one non-empty field value can't be used, or null when it is fine. */
    public function validate(string $key, string $value): ?string;

    /**
     * The connector built from the saved settings, or null while they are incomplete. $testBase is the local mock's
     * address in the test suite only (App passes '' otherwise).
     */
    public function build(Settings $settings, string $testBase): ?InventorySource;

    /** One paragraph for the Integrations page: what comes over and how often. */
    public function intro(): string;

    /**
     * How to create the API access in the vendor's console, step by step.
     *
     * @return list<string>
     */
    public function setupSteps(): array;
}

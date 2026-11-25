<?php

declare(strict_types=1);

namespace Sentinel\Inventory;

use Sentinel\Core\Settings;

/**
 * NinjaOne as a kind of inventory source (1.52; the settings and checks are the ones the Integrations page used since
 * 1.14, moved here unchanged). Settings: ninjaone_host, ninjaone_client_id, ninjaone_client_secret (encrypted).
 *
 * Untrusted: the form values. The instance must be a *.ninjarmm.com host name, so the client secret is only ever sent
 * to NinjaOne; the client ID and secret are limited in length and characters.
 */
final class NinjaOneType implements SourceType
{
    /** {@inheritDoc} */
    public function name(): string
    {
        return 'ninjaone';
    }

    /** {@inheritDoc} */
    public function label(): string
    {
        return 'NinjaOne';
    }

    /** {@inheritDoc} */
    public function fields(): array
    {
        return [
            ['key' => 'host', 'label' => __('Instance'), 'secret' => false, 'maxlength' => 100, 'placeholder' => 'app.ninjarmm.com', 'account' => true,
             'help' => __('The address you sign in to NinjaOne at.'),
             'suggestions' => ['app.ninjarmm.com', 'us2.ninjarmm.com', 'eu.ninjarmm.com', 'ca.ninjarmm.com', 'oc.ninjarmm.com']],
            ['key' => 'client_id', 'label' => __('Client ID'), 'secret' => false, 'maxlength' => 200],
            ['key' => 'client_secret', 'label' => __('Client secret'), 'secret' => true, 'maxlength' => 500],
        ];
    }

    /** {@inheritDoc} The instance: lower case, and a pasted URL becomes its host name. */
    public function normalise(string $key, string $value): string
    {
        $value = $key === 'client_secret' ? $value : trim($value);
        if ($key === 'host') {
            $value = (string) preg_replace('#^https?://|/.*$#', '', strtolower($value));
        }
        return $value;
    }

    /** {@inheritDoc} */
    public function validate(string $key, string $value): ?string
    {
        return match ($key) {
            'host' => NinjaOneSource::validHost($value) ? null
                : __('The NinjaOne instance must be the address you sign in at, ending in .ninjarmm.com (for example app.ninjarmm.com or eu.ninjarmm.com).'),
            'client_id' => preg_match('/^[A-Za-z0-9._~-]{4,200}$/', $value) === 1 ? null : __('The client ID has unexpected characters. Copy it again from NinjaOne.'),
            'client_secret' => strlen($value) <= 500 && preg_match('/[\x00-\x1F\x7F]/', $value) !== 1 ? null : __('The client secret has unexpected characters. Copy it again from NinjaOne.'),
            default => __('Unknown setting.'),
        };
    }

    /** {@inheritDoc} */
    public function build(Settings $settings, string $testBase): ?InventorySource
    {
        $host = $settings->get('ninjaone_host');
        $id = $settings->get('ninjaone_client_id');
        $secret = $settings->getSecret('ninjaone_client_secret');
        if ($host === '' || $id === '' || $secret === '') {
            return null;
        }
        return new NinjaOneSource($host, $id, $secret, $testBase);
    }

    /** {@inheritDoc} */
    public function intro(): string
    {
        return __('Brings each linked client\'s devices into Sentinel every 6 hours: operating system and its support date, antivirus, disk encryption (BitLocker), missing Windows updates and installed software, which is checked for known vulnerabilities. Link a client to its NinjaOne organization on the client\'s Devices page.');
    }

    /** {@inheritDoc} */
    public function setupSteps(): array
    {
        return [
            __('In NinjaOne, go to Administration → Apps → API, and open the Client App IDs tab. Click Add client app.'),
            __('Application platform: API Services (machine-to-machine). Name: MSP Sentinel.'),
            __('Scopes: Monitoring only (read-only). Allowed grant types: Client credentials.'),
            __('Save, then copy the client ID and the client secret into the form below. NinjaOne shows the secret only once.'),
        ];
    }
}

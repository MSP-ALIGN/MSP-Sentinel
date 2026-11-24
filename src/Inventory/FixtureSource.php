<?php

declare(strict_types=1);

namespace Sentinel\Inventory;

/**
 * An inventory source read from a JSON file, for the test suite and demos
 * only (App enables it only in test mode). The file holds
 * {"organisations":[{id,name}], "snapshots":{orgId:{devices:[...], complete:bool}}, "fail":[orgId...]}
 * with normalised devices (see InventorySource).
 *
 * Untrusted: the file's content is treated like any source data.
 */
final class FixtureSource implements InventorySource
{
    /** @param string $file Path to the JSON file (read on every call, so tests can change it). */
    public function __construct(private readonly string $file, private readonly string $sourceName = 'ninjaone', private readonly string $sourceLabel = 'NinjaOne')
    {
    }

    /** {@inheritDoc} */
    public function name(): string
    {
        return $this->sourceName;
    }

    /** {@inheritDoc} */
    public function label(): string
    {
        return $this->sourceLabel;
    }

    /** {@inheritDoc} */
    public function organisations(): array
    {
        return array_values(array_map(static fn (array $o): array => ['id' => (string) $o['id'], 'name' => (string) $o['name']], (array) ($this->data()['organisations'] ?? [])));
    }

    /** {@inheritDoc} */
    public function snapshot(string $orgId): array
    {
        $data = $this->data();
        if (in_array($orgId, (array) ($data['fail'] ?? []), true)) {
            throw new InventoryException('The source refused the request (test failure).');
        }
        $snap = (array) ($data['snapshots'][$orgId] ?? ['devices' => [], 'complete' => true]);
        return ['devices' => array_values((array) ($snap['devices'] ?? [])), 'complete' => ($snap['complete'] ?? true) === true];
    }

    /** @return array<string,mixed> */
    private function data(): array
    {
        $raw = is_file($this->file) ? (string) file_get_contents($this->file) : '';
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            throw new InventoryException('The test inventory file is missing or not valid JSON.');
        }
        return $data;
    }
}

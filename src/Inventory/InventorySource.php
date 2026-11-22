<?php

declare(strict_types=1);

namespace Sentinel\Inventory;

/**
 * An inventory source: a system that already knows a client's devices
 * (NinjaOne first; the on-premises agent later). Sources are read-only:
 * Sentinel only reads from them and never sends anything to a device.
 *
 * Everything a source returns is untrusted text from an outside system;
 * InventoryRepository cleans and shortens it before it is stored.
 *
 * Normalised device (all keys required, '' or [] when unknown):
 *   source_id string, name string, dns_name string, device_class string
 *   ('workstation'|'server'|'other'), os_name string, os_build string,
 *   os_release string, ip_addresses list<string>, last_contact ?int (Unix time),
 *   av_product string, av_state ('on'|'off'|'missing'|''), av_definitions
 *   ('current'|'outdated'|''), encryption ('on'|'off'|''),
 *   software list<{name,publisher,version}>,
 *   patches list<{patch_id,name,kb,severity,status,detected_at:?int}>
 *   (status 'pending'|'failed'; only missing patches are listed).
 */
interface InventorySource
{
    /** Short machine name, stored with every device and finding (e.g. "ninjaone"). */
    public function name(): string;

    /** Name for people (e.g. "NinjaOne"). */
    public function label(): string;

    /**
     * Organisations in the source, for an admin to link to clients.
     *
     * @return list<array{id:string, name:string}>
     * @throws InventoryException When the source can't be reached or refuses.
     */
    public function organisations(): array;

    /**
     * Everything the source knows about one organisation's devices.
     *
     * @return array{devices:list<array<string,mixed>>, complete:bool} complete is false when the
     *         source returned only part of the data (e.g. a page failed): devices missing from a
     *         partial snapshot must not be marked as removed.
     * @throws InventoryException When the source can't be reached or refuses.
     */
    public function snapshot(string $orgId): array;
}

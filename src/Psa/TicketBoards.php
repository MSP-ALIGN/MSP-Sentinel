<?php

declare(strict_types=1);

namespace Sentinel\Psa;

use Sentinel\Core\Settings;

/**
 * An optional extra for PSAs with service boards (1.53): new tickets can be moved to a chosen board. Only some PSAs
 * (and only some ITFlow builds) have boards; the workflow checks for this interface before using it.
 */
interface TicketBoards
{
    /**
     * Read the boards and keep the list for the Integrations page; null when the PSA has no boards.
     *
     * @return list<array{id:int|string, name:string, is_default:bool}>|null
     * @throws PsaException
     */
    public function refreshBoards(Settings $settings): ?array;

    /**
     * The default board for Sentinel's tickets from a list (e.g. the one named "Alerts"), or null.
     *
     * @param list<array{id:int|string, name:string, is_default:bool}> $boards
     * @return array{id:int|string, name:string, is_default:bool}|null
     */
    public function defaultBoard(array $boards): ?array;

    /** Move a ticket to a board, optionally unassigned so the board's own rules pick it up. @throws PsaException */
    public function moveTicket(int|string $clientId, int|string $ticketId, int|string $boardId, bool $unassign = true): void;
}

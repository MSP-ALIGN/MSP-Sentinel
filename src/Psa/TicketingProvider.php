<?php

declare(strict_types=1);

namespace Sentinel\Psa;

/**
 * A ticketing system (PSA) as the ticket workflow uses it (1.53): open a ticket, find one again, add internal notes,
 * read its state, resolve and reopen it, and link to it. ITFlow is the first (ItflowProvider).
 *
 * IDs are the PSA's own (an integer or a string, depending on the PSA): the client ID from the client's link and the
 * ticket ID the PSA returned. Priorities are Sentinel's: Low, Medium, High, Urgent; the adapter maps them.
 *
 * Untrusted: everything the PSA returns. Callers escape HTML they send (notes and details are HTML the caller built
 * with every value escaped). Every method throws PsaException when the PSA can't be reached or refuses.
 */
interface TicketingProvider
{
    /** Short machine name (e.g. "itflow"). */
    public function name(): string;

    /** Name for people (e.g. "ITFlow"). */
    public function label(): string;

    /**
     * What this PSA can do, so the workflow adapts instead of assuming: reopen_closed (a closed ticket can be reopened;
     * if not, a replacement is opened) and markers (a ticket can be found again by its marker after a create timed out;
     * if not, a timed-out create may leave a duplicate).
     *
     * @return array{reopen_closed:bool, markers:bool}
     */
    public function capabilities(): array;

    /**
     * Open an internal ticket (the client is not emailed).
     *
     * @return array{id:int|string, reference:string}
     */
    public function createTicket(int|string $clientId, string $subject, string $detailsHtml, string $priority, string $marker = ''): array;

    /**
     * The ticket opened with this marker since $notBefore (UTC), or null (only when capabilities()['markers']).
     *
     * @return array{id:int|string, reference:string}|null
     */
    public function findByMarker(int|string $clientId, string $marker, string $notBefore = ''): ?array;

    /** Add an internal note (not emailed to the client). */
    public function addNote(int|string $clientId, int|string $ticketId, string $html): void;

    /** The ticket's state: open (any working status), resolved, closed, or gone (deleted or out of reach). */
    public function ticketStatus(int|string $ticketId): string;

    /** Resolve a ticket. */
    public function resolveTicket(int|string $clientId, int|string $ticketId): void;

    /** Reopen a resolved ticket (and a closed one when capabilities()['reopen_closed']). */
    public function reopenTicket(int|string $clientId, int|string $ticketId): void;

    /** A link to the ticket for technicians (never one holding a secret), or '' when none can be built. */
    public function ticketUrl(int|string $clientId, int|string $ticketId): string;
}

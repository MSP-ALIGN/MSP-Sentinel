<?php

declare(strict_types=1);

namespace Sentinel\Psa;

use Sentinel\Core\Settings;
use Sentinel\Itflow\ItflowClient;

/**
 * ITFlow as a ticketing system (1.53): a thin adapter over ItflowClient, which is unchanged. ITFlow IDs are integers,
 * so IDs from the workflow are checked to be whole numbers before they are sent (anything else is refused).
 *
 * Capabilities: ITFlow can't reopen a closed ticket (a replacement is opened), and finds a ticket again by the marker
 * stored in it. It has service boards on builds that support them, and client tags on builds with the tags API.
 */
final class ItflowProvider implements TicketingProvider, TicketBoards, ClientDirectory, ClientTags
{
    /** @param int $templateId An ITFlow ticket template for new tickets (1.56; 0 = none): their category comes from it. */
    public function __construct(private readonly ItflowClient $client, private readonly string $baseUrl, private readonly bool $allowHttp = false, private readonly int $templateId = 0)
    {
    }

    /** {@inheritDoc} */
    public function name(): string
    {
        return 'itflow';
    }

    /** {@inheritDoc} */
    public function label(): string
    {
        return 'ITFlow';
    }

    /** {@inheritDoc} */
    public function capabilities(): array
    {
        return ['reopen_closed' => false, 'markers' => true];
    }

    /** {@inheritDoc} */
    public function createTicket(int|string $clientId, string $subject, string $detailsHtml, string $priority, string $marker = ''): array
    {
        return $this->client->createTicket(self::id($clientId), $subject, $detailsHtml, $priority, $marker, $this->templateId);
    }

    /** {@inheritDoc} */
    public function findByMarker(int|string $clientId, string $marker, string $notBefore = ''): ?array
    {
        return $this->client->findByMarker(self::id($clientId), $marker, $notBefore);
    }

    /** {@inheritDoc} */
    public function addNote(int|string $clientId, int|string $ticketId, string $html): void
    {
        $this->client->addNote(self::id($clientId), self::id($ticketId), $html);
    }

    /** {@inheritDoc} */
    public function ticketStatus(int|string $ticketId): string
    {
        return $this->client->ticketStatus(self::id($ticketId));
    }

    /** {@inheritDoc} */
    public function resolveTicket(int|string $clientId, int|string $ticketId): void
    {
        $this->client->resolveTicket(self::id($clientId), self::id($ticketId));
    }

    /** {@inheritDoc} */
    public function reopenTicket(int|string $clientId, int|string $ticketId): void
    {
        $this->client->reopenTicket(self::id($clientId), self::id($ticketId));
    }

    /** {@inheritDoc} ITFlow's agent view of the ticket. */
    public function ticketUrl(int|string $clientId, int|string $ticketId): string
    {
        return ItflowClient::ticketUrl($this->baseUrl, self::id($clientId), self::id($ticketId), $this->allowHttp);
    }

    /** {@inheritDoc} */
    public function refreshBoards(Settings $settings): ?array
    {
        return $this->client->refreshBoards($settings);
    }

    /** {@inheritDoc} The board named "Alerts". */
    public function defaultBoard(array $boards): ?array
    {
        return ItflowClient::alertsBoard($boards);
    }

    /** {@inheritDoc} */
    public function moveTicket(int|string $clientId, int|string $ticketId, int|string $boardId, bool $unassign = true): void
    {
        $this->client->moveTicket(self::id($clientId), self::id($ticketId), self::id($boardId), $unassign);
    }

    /** {@inheritDoc} */
    public function clients(): array
    {
        return $this->client->clients();
    }

    /** {@inheritDoc} */
    public function taggedClientIds(string $tagName): ?array
    {
        return $this->client->taggedClientIds($tagName);
    }

    /** An ITFlow ID: a positive whole number (as int or digits), else the request is refused without being sent. */
    private static function id(int|string $id): int
    {
        if (is_int($id) ? $id > 0 : (ctype_digit($id) && strlen($id) <= 10 && (int) $id > 0)) {
            return (int) $id;
        }
        throw new PsaException('Not an ITFlow ID.', PsaException::KIND_REFUSED);
    }
}

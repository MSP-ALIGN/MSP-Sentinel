<?php

declare(strict_types=1);

namespace Sentinel\Itflow;

/**
 * ITFlow could not be read or refused a request. The message is safe to show (never holds the key).
 *
 * The kind says what the caller can conclude:
 * - KIND_AUTH: the key was refused (401) - every later call fails too, so a run stops.
 * - KIND_UNREACHABLE: no answer, a timeout, a server error (5xx) or an answer that isn't ITFlow's - a run stops, and
 *   for a write it is unknown whether ITFlow did it.
 * - KIND_REFUSED: ITFlow answered and refused this one request (400, 403, or success False) - it did not do it; other
 *   requests may still work, so a run carries on with the next item.
 */
final class ItflowException extends \RuntimeException
{
    public const KIND_AUTH = 'auth';
    public const KIND_UNREACHABLE = 'unreachable';
    public const KIND_REFUSED = 'refused';

    public function __construct(string $message, public readonly string $kind = self::KIND_UNREACHABLE)
    {
        parent::__construct($message);
    }

    /** Whether the whole run should stop (rather than skip this one item). */
    public function stopsRun(): bool
    {
        return $this->kind !== self::KIND_REFUSED;
    }
}

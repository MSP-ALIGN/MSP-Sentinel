<?php

declare(strict_types=1);

namespace Sentinel\Psa;

/**
 * A ticketing system (PSA) could not be read or refused a request (1.53; the kinds are ITFlow's from before, now shared
 * by every PSA adapter). The message is safe to show (never holds a key).
 *
 * The kind says what the caller can conclude:
 * - KIND_AUTH: the key was refused - every later call fails too, so a run stops.
 * - KIND_UNREACHABLE: no answer, a timeout, a server error or an answer that isn't the PSA's - a run stops, and for a
 *   write it is unknown whether the PSA did it.
 * - KIND_REFUSED: the PSA answered and refused this one request - it did not do it; other requests may still work, so
 *   a run carries on with the next item.
 */
class PsaException extends \RuntimeException
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

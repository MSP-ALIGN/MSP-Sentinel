<?php

declare(strict_types=1);

namespace Sentinel\Itflow;

use Sentinel\Psa\PsaException;

/**
 * ITFlow could not be read or refused a request. The message is safe to show (never holds the key).
 *
 * The kinds (KIND_AUTH, KIND_UNREACHABLE, KIND_REFUSED) and stopsRun() come from PsaException (1.53), so the ticket
 * workflow handles every PSA's errors the same way:
 * - KIND_AUTH: the key was refused (401) - every later call fails too, so a run stops.
 * - KIND_UNREACHABLE: no answer, a timeout, a server error (5xx) or an answer that isn't ITFlow's - a run stops, and
 *   for a write it is unknown whether ITFlow did it.
 * - KIND_REFUSED: ITFlow answered and refused this one request (400, 403, or success False) - it did not do it; other
 *   requests may still work, so a run carries on with the next item.
 */
final class ItflowException extends PsaException
{
}

<?php

declare(strict_types=1);

namespace Sentinel\Core;

/**
 * An error that maps to an HTTP status and a user-safe message.
 *
 * Security assumptions: the message is shown to the user, so it must never
 * contain internal details (SQL, paths, secrets). Use a generic message and
 * log the details separately.
 */
final class HttpException extends \RuntimeException
{
    /** HTTP status plus a user-safe message ("" for the default text). */
    public function __construct(public readonly int $status, string $userMessage = '')
    {
        parent::__construct($userMessage);
    }
}

<?php

declare(strict_types=1);

namespace Sentinel\Api;

/**
 * An API error with an HTTP status and a message that is safe to show the caller.
 */
final class ApiError extends \RuntimeException
{
    /** @param string $message Safe for the caller (no internal details). */
    public function __construct(public readonly int $status, string $message)
    {
        parent::__construct($message);
    }
}

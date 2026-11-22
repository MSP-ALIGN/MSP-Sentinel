<?php

declare(strict_types=1);

namespace Sentinel\Vulns;

/**
 * A feed refused the request because of rate limiting or unavailability
 * (HTTP 403, 429 or 503). Callers must stop sending requests until
 * $retryAfterSeconds have passed, rather than making the ban longer.
 */
final class RateLimited extends \RuntimeException
{
    /** @param int $retryAfterSeconds From the Retry-After header (or a safe default). */
    public function __construct(string $message, public readonly int $retryAfterSeconds)
    {
        parent::__construct($message);
    }
}

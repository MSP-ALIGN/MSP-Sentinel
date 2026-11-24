<?php

declare(strict_types=1);

namespace Sentinel\Discovery;

/**
 * Internal signal: a discovery run had to stop early (time budget, query cap,
 * kill switch, or an unreachable resolver). The message is shown to users.
 */
final class DiscoveryStopped extends \RuntimeException
{
    /** @param bool $failed True if nothing useful could be done (the run is marked failed, not partial). */
    public function __construct(string $message, public readonly bool $failed)
    {
        parent::__construct($message);
    }
}

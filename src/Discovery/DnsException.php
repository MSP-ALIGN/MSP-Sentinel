<?php

declare(strict_types=1);

namespace Sentinel\Discovery;

/**
 * A DNS lookup failed (timeout, server failure, or a malformed or mismatched
 * response). The message is safe to show to admins: it never contains packet bytes.
 */
final class DnsException extends \RuntimeException
{
}

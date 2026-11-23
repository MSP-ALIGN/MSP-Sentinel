<?php

declare(strict_types=1);

namespace Sentinel\Directory;

/** The domain controller couldn't be reached, refused, or answered unexpectedly. Safe to show (never holds a password). */
final class LdapException extends \RuntimeException
{
}

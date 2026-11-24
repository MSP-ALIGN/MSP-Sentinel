<?php

declare(strict_types=1);

namespace Sentinel\Directory;

/** Malformed BER/LDAP data from the other side. The message is safe to show (never holds a password). */
final class BerException extends \RuntimeException
{
}

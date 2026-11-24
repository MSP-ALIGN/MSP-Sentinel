<?php

declare(strict_types=1);

namespace Sentinel\Auth;

/** A "Sign in with Microsoft" failure (1.43). The message is safe to show and to log: never a token or secret. */
final class SsoException extends \RuntimeException
{
}

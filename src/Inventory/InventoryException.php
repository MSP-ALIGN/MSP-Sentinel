<?php

declare(strict_types=1);

namespace Sentinel\Inventory;

/** An inventory source could not be reached, refused the request or answered badly. The message is safe to show (no secrets). */
final class InventoryException extends \RuntimeException
{
}

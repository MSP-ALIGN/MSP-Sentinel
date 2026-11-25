<?php

declare(strict_types=1);

namespace Sentinel\Psa;

/**
 * An optional extra for PSAs whose clients can be tagged (1.53): the sync can be limited to clients with one tag.
 */
interface ClientTags
{
    /**
     * IDs of the clients with this tag, or null when the PSA can't say (the sync then changes nothing).
     *
     * @return list<int|string>|null
     * @throws PsaException
     */
    public function taggedClientIds(string $tagName): ?array;
}

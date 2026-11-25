<?php

declare(strict_types=1);

namespace Sentinel\Psa;

/**
 * A PSA's client list, for the client sync (1.53): add, rename, archive and restore Sentinel's clients to match.
 */
interface ClientDirectory
{
    /**
     * Every client in the PSA.
     *
     * @return list<array{id:int|string, name:string, archived:bool}>
     * @throws PsaException
     */
    public function clients(): array;
}

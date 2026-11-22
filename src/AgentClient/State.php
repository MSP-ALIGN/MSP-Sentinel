<?php

declare(strict_types=1);

namespace Sentinel\AgentClient;

/**
 * The agent's small local state: the IDs of jobs it already ran (so a job
 * can never be replayed). Stored as JSON, written atomically, readable only
 * by the agent's user.
 */
final class State
{
    private const KEEP = 1000;

    /** @param string $file State file path (e.g. /var/lib/sentinel-agent/state.json). */
    public function __construct(private readonly string $file)
    {
    }

    /** @return list<int> */
    public function doneIds(): array
    {
        $data = is_file($this->file) ? json_decode((string) file_get_contents($this->file), true) : null;
        return is_array($data) ? array_values(array_filter((array) ($data['done'] ?? []), 'is_int')) : [];
    }

    /** Remember that a job ran. */
    public function markDone(int $jobId): void
    {
        $done = array_slice(array_values(array_unique([...$this->doneIds(), $jobId])), -self::KEEP);
        $tmp = $this->file . '.tmp';
        file_put_contents($tmp, json_encode(['done' => $done]));
        chmod($tmp, 0600);
        rename($tmp, $this->file);
    }
}

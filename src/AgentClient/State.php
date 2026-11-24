<?php

declare(strict_types=1);

namespace Sentinel\AgentClient;

/**
 * The agent's small local state: the IDs of jobs it already ran (so a job
 * can never be replayed), and finished results not yet accepted by Sentinel
 * (retried at each check-in). Stored as JSON next to the state file, written
 * atomically, readable only by the agent's user.
 */
final class State
{
    private const KEEP = 1000;

    /** @param string $file State file path (e.g. /var/lib/sentinel-agent/state.json). */
    public function __construct(private readonly string $file)
    {
    }

    /** The folder the state lives in. */
    public function directory(): string
    {
        return dirname($this->file);
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

    /**
     * Keep a job's results until Sentinel has accepted them.
     *
     * @param array<string,mixed> $results
     */
    public function savePending(int $jobId, array $results): void
    {
        $file = $this->pendingFile($jobId);
        file_put_contents($file . '.tmp', json_encode($results, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
        chmod($file . '.tmp', 0600);
        rename($file . '.tmp', $file);
    }

    /**
     * Results waiting to be sent, oldest job first.
     *
     * @return array<int,array<string,mixed>> job ID => results
     */
    public function pending(): array
    {
        $out = [];
        foreach (glob(dirname($this->file) . '/pending-*.json') ?: [] as $f) {
            if (preg_match('/pending-(\d{1,10})\.json$/', $f, $m)) {
                $data = json_decode((string) file_get_contents($f), true);
                if (is_array($data)) {
                    $out[(int) $m[1]] = $data;
                } else {
                    @unlink($f);
                }
            }
        }
        ksort($out);
        return $out;
    }

    /** Sentinel accepted (or no longer wants) a job's results. */
    public function clearPending(int $jobId): void
    {
        @unlink($this->pendingFile($jobId));
    }

    private function pendingFile(int $jobId): string
    {
        return dirname($this->file) . '/pending-' . $jobId . '.json';
    }
}

<?php

declare(strict_types=1);

namespace Sentinel\System;

use Sentinel\Core\Settings;

/**
 * Small jobs the worker runs on every tick: records a heartbeat (for the
 * health check), and once a day checks for updates and applies data retention.
 * Each part is isolated, so one failing never stops the others or the scans.
 *
 * Security assumptions: no input; see UpdateChecker and Retention.
 */
final class Housekeeping
{
    /**
     * Wires the parts.
     *
     * @param (callable(): ?string)|null $itflowSync The ITFlow client sync (it runs only when due: every 15 minutes).
     * @param (callable(): ?string)|null $itflowTickets ITFlow tickets from findings (when due: every 5 minutes).
     */
    public function __construct(private readonly Settings $settings, private readonly UpdateChecker $updates, private readonly Retention $retention,
        private $itflowSync = null, private $itflowTickets = null)
    {
    }

    /** Run what is due. */
    public function tick(): void
    {
        $this->settings->set('worker_last_tick', gmdate('Y-m-d H:i:s'));
        foreach ([fn () => $this->updates->check(), fn () => $this->retention->run(), fn () => $this->itflowSync === null ? null : ($this->itflowSync)(),
                  fn () => $this->itflowTickets === null ? null : ($this->itflowTickets)()] as $job) {
            try {
                $job();
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] housekeeping: ' . $ex->getMessage());
            }
        }
    }
}

<?php
/**
 * On-premises agents card on the client's pages: per site, the internal authorisation, agents, kill switch and recent scans.
 * Expects: $client, $agentSites (ClientController::agentSites), $currentUser, $globallyPaused.
 * Agent-reported names and versions, and the directory certificate subject the agent saw, are untrusted and escaped.
 * The directory password is never on this page: only its sealed state (where it is) is shown.
 */
use Sentinel\Auth\Role;
use Sentinel\Core\Csrf;

$isAdmin = Role::atLeast((string) $currentUser['role'], Role::ADMIN);
$isTech = Role::atLeast((string) $currentUser['role'], Role::TECHNICIAN);
$agentRelease = \Sentinel\Core\App::agentRelease()->version(); // the signed agent release this Sentinel can hand out
$cid = (int) $client['id'];
$jobLabel = static fn (array $j): string => match ($j['status']) {
    'done' => __('done'), 'partial' => __('partial'), 'failed' => __('failed'), 'cancelled' => __('cancelled'), 'expired' => __('expired (agent offline?)'),
    'sent' => __('running'), default => __('waiting for the agent'),
};
?>
<div class="card mb-3" id="agents">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('On-premises agents (internal scans)')) ?></h2></div>
    <div class="card-body">
        <?php if ($isAdmin && $agentRelease !== null): ?>
        <form method="post" action="<?= e(url('/clients/' . $cid . '/agents-update')) ?>" class="float-end ms-2" data-confirm="<?= e(__('Update every agent of this client that runs an older version to {v}?', ['v' => $agentRelease])) ?>"><?= Csrf::field() ?>
            <button class="btn btn-sm btn-outline-primary" type="submit"><i class="bi bi-cloud-arrow-down me-1" aria-hidden="true"></i><?= e(__('Update all agents to {v}', ['v' => $agentRelease])) ?></button></form>
        <?php endif; ?>
        <p class="small text-body-secondary"><?= e(__('An agent is a small Linux appliance at the client\'s site. It connects out to Sentinel, scans only the internal networks approved in a signed internal authorisation, and reports devices, open services and certificates. A full scan runs weekly and a light sweep daily, inside the scan window.')) ?></p>
        <?php $anyAgent = array_filter($agentSites, static fn (array $s): bool => $s['agents'] !== []) !== []; ?>
        <details class="border rounded p-2 mb-3 small" <?= $anyAgent ? '' : 'open' ?>>
            <summary class="fw-semibold"><?= e(__('How to add an agent')) ?></summary>
            <ol class="mt-2 mb-1">
                <li><?= e(__('Record an internal authorisation for the site below: who at the client approved internal scanning, the dates, and the private networks to scan.')) ?></li>
                <li><?= e(__('Prepare a mini-PC or VM at the site that stays on: Debian 13 (or Debian 12 / Ubuntu 24.04), 2 CPU cores, 2 GB memory, 20 GB disk, on the internal network (a VM needs a bridged adapter, not NAT), with outbound HTTPS to Sentinel. No inbound firewall rule is needed. Or a Windows Server 2022/2025 or Windows 11 machine.')) ?></li>
                <li><?= e(__('Click Create an enrolment code for the site (admins). The next page shows the code once, the install command for your Sentinel address with a copy button, and how to check it worked.')) ?></li>
                <li><?= e(__('Run the command on the appliance and type the code when asked. The agent shows up here within a minute, and scans inside the client\'s scan window.')) ?></li>
            </ol>
            <a href="<?= e(url('/help')) ?>#on-premises-agents-internal-scans"><?= e(__('More in Help')) ?></a>
        </details>
        <?php foreach ($agentSites as $s): $site = $s['site']; $sid = (int) $site['id']; ?>
        <div class="border rounded p-3 mb-3">
            <div class="d-flex flex-wrap align-items-center gap-2 mb-2">
                <h3 class="h6 mb-0"><i class="bi bi-building me-1" aria-hidden="true"></i><?= e($site['name']) ?></h3>
                <?php if ((int) $site['scanning_paused'] === 1): ?><span class="badge text-bg-warning"><i class="bi bi-pause-circle me-1" aria-hidden="true"></i><?= e(__('Agent scans paused')) ?></span><?php endif; ?>
                <span class="ms-auto d-flex gap-2">
                <?php if ((int) $site['scanning_paused'] === 0 && $isTech): ?>
                    <form method="post" action="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/pause')) ?>" data-confirm="<?= e(__('Stop agent scans at this site now?')) ?>"><?= Csrf::field() ?><button class="btn btn-sm btn-outline-danger" type="submit"><i class="bi bi-stop-circle me-1" aria-hidden="true"></i><?= e(__('Pause')) ?></button></form>
                <?php elseif ((int) $site['scanning_paused'] === 1 && $isAdmin): ?>
                    <form method="post" data-confirm="<?= e(__('Resume scanning for this site? Its agent starts taking scans again.')) ?>" action="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/resume')) ?>"><?= Csrf::field() ?><button class="btn btn-sm btn-outline-primary" type="submit"><?= e(__('Resume')) ?></button></form>
                <?php endif; ?>
                </span>
            </div>
            <div class="small mb-2">
                <strong><?= e(__('Internal authorisation:')) ?></strong>
                <?php if ($s['active'] === null): ?>
                    <span class="text-body-secondary"><?= e(__('none valid. Agents at this site do not scan.')) ?></span>
                <?php else: ?>
                    <span class="font-monospace"><?= e(implode(', ', $s['active']['ranges_list'])) ?></span>
                    <span class="text-body-secondary">· <?= e(__('approved by {name}, valid until {date}', ['name' => $s['active']['approved_by_name'], 'date' => $s['active']['valid_until']])) ?></span>
                    <i class="bi bi-patch-check text-success" aria-hidden="true"></i><span class="visually-hidden"><?= e(__('signed')) ?></span>
                    <?php if ($isAdmin): ?>
                    <details class="d-inline-block ms-2"><summary class="text-danger"><?= e(__('Revoke')) ?></summary>
                        <form method="post" data-confirm="<?= e(__('Revoke this internal authorisation? The site\'s agent stops scanning straight away and nothing internal is scanned until a new one is recorded.')) ?>" action="<?= e(url('/clients/' . $cid . '/internal-authorisations/' . (int) $s['active']['id'] . '/revoke')) ?>" class="d-flex gap-2 mt-1"><?= Csrf::field() ?>
                            <input class="form-control form-control-sm" name="reason" maxlength="500" placeholder="<?= e(__('Reason (required)')) ?>" required aria-label="<?= e(__('Reason')) ?>">
                            <button class="btn btn-sm btn-danger" type="submit"><?= e(__('Revoke')) ?></button></form></details>
                    <?php endif; ?>
                <?php endif; ?>
                <?php if ($isAdmin): ?> <a class="ms-2" href="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/internal-authorisations/new')) ?>"><?= e(__('Record a new internal authorisation')) ?></a><?php endif; ?>
            </div>
            <div class="table-responsive">
            <table class="table table-sm small align-middle mb-2">
                <thead><tr><th><?= e(__('Agent')) ?></th><th><?= e(__('Version')) ?></th><th><?= e(__('Last check-in (UTC)')) ?></th><th><?= e(__('Status')) ?></th><th></th></tr></thead>
                <tbody>
                <?php if ($s['agents'] === []): ?><tr><td colspan="5" class="text-body-secondary"><?= e(__('No agent enrolled yet.')) ?></td></tr><?php endif; ?>
                <?php foreach ($s['agents'] as $a): $online = $a['last_seen_at'] !== null && strtotime($a['last_seen_at'] . ' UTC') > time() - 600; ?>
                <tr>
                    <td><?= e($a['name']) ?><div class="text-body-secondary"><?= e($a['last_ip']) ?></div>
                        <?php if ($a['status'] === 'active' && (string) $a['box_public_key'] !== ''): ?><div class="text-body-secondary small"><?= e(__('Key')) ?> <span class="font-monospace"><?= e(\Sentinel\AgentClient\AgentKey::fingerprint((string) $a['box_public_key'])) ?></span></div><?php endif; ?>
                        <?php if ($a['status'] === 'active' && (string) ($a['box_key_pending'] ?? '') !== ''): $pfp = \Sentinel\AgentClient\AgentKey::fingerprint((string) $a['box_key_pending']); ?>
                        <div class="alert alert-warning small py-1 px-2 mt-1 mb-0"><?= e(__('The agent reported a NEW key {fp} ({t} UTC). Passwords are not sealed to it until an admin approves it. Approve only if the agent was reinstalled and its status command shows this fingerprint.', ['fp' => $pfp, 't' => $a['box_key_pending_at']])) ?>
                            <?php if ($isAdmin): ?><form method="post" action="<?= e(url('/clients/' . $cid . '/agents/' . (int) $a['id'] . '/approve-key')) ?>" class="mt-1" data-confirm="<?= e(__('Approve this new agent key? Compare the fingerprint with the agent\'s status output first.')) ?>"><?= Csrf::field() ?>
                                <input type="hidden" name="fingerprint" value="<?= e($pfp) ?>"><button class="btn btn-sm btn-outline-warning" type="submit"><?= e(__('Approve new key')) ?></button></form><?php endif; ?></div>
                        <?php endif; ?></td>
                    <td class="font-monospace"><?= e($a['version'] ?: '?') ?>
                        <?php if ($a['status'] === 'active' && preg_match('/^\d+\.\d+\.\d+$/', (string) $a['version']) === 1 && version_compare((string) $a['version'], '1.21.0', '<')): ?>
                        <div class="small text-warning font-sans-serif"><?= e(__('Upgrade this agent: before 1.21.0 it ignores the gentleness setting, Restart and Diagnostics.')) ?></div><?php endif; ?>
                        <?php if ($a['status'] === 'active' && (string) ($a['update_to'] ?? '') !== ''): ?><div class="small text-body-secondary"><?= e(__('update to {v} requested', ['v' => $a['update_to']])) ?></div><?php endif; ?>
                        <?php $ur = json_decode((string) ($a['update_result'] ?? ''), true); if ($a['status'] === 'active' && is_array($ur)): ?>
                        <div class="small <?= ($ur['ok'] ?? false) ? 'text-success' : 'text-danger' ?>"><?= e(($ur['ok'] ?? false) ? __('Updated to {v} ({t} UTC)', ['v' => $ur['version'] ?? '?', 't' => $a['update_result_at']]) : __('Update to {v} refused: {why}', ['v' => $ur['version'] ?? '?', 'why' => $ur['message'] ?? ''])) ?></div><?php endif; ?></td>
                    <td><?= e((string) ($a['last_seen_at'] ?? '-')) ?></td>
                    <td><?php if ($a['status'] === 'revoked'): ?><span class="badge text-bg-secondary"><?= e(__('Revoked')) ?></span>
                        <?php elseif ($online): ?><span class="badge text-bg-success"><i class="bi bi-wifi me-1" aria-hidden="true"></i><?= e(__('Online')) ?></span>
                        <?php else: ?><span class="badge text-bg-warning"><i class="bi bi-wifi-off me-1" aria-hidden="true"></i><?= e(__('Offline')) ?></span><?php endif; ?></td>
                    <td class="text-end"><?php if ($isAdmin && $a['status'] === 'active'): ?>
                        <div class="d-flex flex-wrap gap-1 justify-content-end">
                        <?php if ($agentRelease !== null && \Sentinel\System\ReleaseManifest::newer($agentRelease, (string) $a['version']) && \Sentinel\Agent\AgentRepository::canUpdateRemotely((string) $a['version']) && (string) ($a['update_to'] ?? '') !== $agentRelease): ?>
                        <form method="post" action="<?= e(url('/clients/' . $cid . '/agents/' . (int) $a['id'] . '/update')) ?>" data-confirm="<?= e(__('Update this agent to {v} at its next check-in between scans?', ['v' => $agentRelease])) ?>"><?= Csrf::field() ?><button class="btn btn-sm btn-primary" type="submit"><i class="bi bi-cloud-arrow-down me-1" aria-hidden="true"></i><?= e(__('Update to {v}', ['v' => $agentRelease])) ?></button></form>
                        <?php endif; ?>
                        <form method="post" action="<?= e(url('/clients/' . $cid . '/agents/' . (int) $a['id'] . '/diagnostics')) ?>"><?= Csrf::field() ?><button class="btn btn-sm btn-outline-secondary" type="submit"><i class="bi bi-clipboard-pulse me-1" aria-hidden="true"></i><?= e(__('Diagnostics')) ?></button></form>
                        <form method="post" action="<?= e(url('/clients/' . $cid . '/agents/' . (int) $a['id'] . '/restart')) ?>" data-confirm="<?= e(__('Restart this agent at its next check-in? A running scan finishes first.')) ?>"><?= Csrf::field() ?><button class="btn btn-sm btn-outline-secondary" type="submit"><i class="bi bi-arrow-clockwise me-1" aria-hidden="true"></i><?= e(__('Restart')) ?></button></form>
                        <form method="post" action="<?= e(url('/clients/' . $cid . '/agents/' . (int) $a['id'] . '/revoke')) ?>" data-confirm="<?= e(__('Revoke this agent? Its token stops working immediately.')) ?>"><?= Csrf::field() ?><button class="btn btn-sm btn-outline-secondary" type="submit"><?= e(__('Revoke')) ?></button></form>
                        </div>
                        <?php if ((int) ($a['restart_requested'] ?? 0) === 1): ?><div class="small text-body-secondary"><?= e(__('restart requested')) ?></div><?php endif; ?>
                        <?php if ((int) ($a['diagnostics_requested'] ?? 0) === 1): ?><div class="small text-body-secondary"><?= e(__('diagnostics requested')) ?></div><?php endif; ?>
                    <?php endif; ?></td>
                </tr>
                <?php $diag = json_decode((string) ($a['diagnostics'] ?? ''), true); if (is_array($diag) && $a['status'] === 'active'): ?>
                <tr><td colspan="5" class="small">
                    <details><summary><?= e(__('Diagnostics reported by the agent, {t} UTC', ['t' => $a['diagnostics_at']])) ?></summary>
                    <?php $reportedFp = (string) ($diag['key_fingerprint'] ?? ''); $knownFp = (string) $a['box_public_key'] !== '' ? \Sentinel\AgentClient\AgentKey::fingerprint((string) $a['box_public_key']) : ''; ?>
                    <?php if ($reportedFp !== '' && $knownFp !== '' && $reportedFp !== $knownFp): ?><div class="alert alert-warning py-1 px-2 my-1"><?= e(__('The key this report names is not the pinned key ({fp}). Compare on the appliance itself (status command) before approving any key.', ['fp' => $knownFp])) ?></div><?php endif; ?>
                    <dl class="row mb-0 mt-1">
                        <?php foreach ([__('Agent version') => $diag['version'] ?? '', __('PHP') => $diag['php'] ?? '', __('System') => $diag['os'] ?? '', __('nmap') => $diag['nmap'] ?? '',
                                        __('Free disk') => isset($diag['disk_free_mb']) ? $diag['disk_free_mb'] . ' MB' : '', __('Free memory') => isset($diag['memory_mb']) ? $diag['memory_mb'] . ' MB' : '',
                                        __('Load') => (string) ($diag['load'] ?? ''), __('Up for') => isset($diag['uptime_seconds']) ? __('{d} day(s)', ['d' => intdiv((int) $diag['uptime_seconds'], 86400)]) : '',
                                        __('Results waiting to upload') => (string) ($diag['pending_results'] ?? ''),
                                        __('Clock difference') => isset($diag['clock_skew_seconds']) ? $diag['clock_skew_seconds'] . ' s' . (abs((int) $diag['clock_skew_seconds']) > 120 ? ' — ' . __('fix the appliance\'s clock (NTP): jobs carry expiry times') : '') : '',
                                        __('Agent key') => $diag['key_fingerprint'] ?? '', __('Directory password held') => ($diag['holds_directory'] ?? false) ? __('yes (sealed)') : __('no'),
                                        __('Name listening') => $diag['name_listening'] ?? ''] as $label => $value): ?>
                        <?php if ((string) $value !== ''): ?><dt class="col-sm-4"><?= e($label) ?></dt><dd class="col-sm-8"><?= e((string) $value) ?></dd><?php endif; ?>
                        <?php endforeach; ?>
                    </dl></details></td></tr>
                <?php endif; ?>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
            <?php if ($isAdmin): ?>
            <form method="post" action="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/agent-settings')) ?>" class="d-flex flex-wrap align-items-end gap-2 mb-2 small"><?= Csrf::field() ?>
                <div><label class="form-label mb-0" for="timing-<?= $sid ?>"><?= e(__('Scan gentleness')) ?></label>
                    <select class="form-select form-select-sm" id="timing-<?= $sid ?>" name="timing">
                        <?php foreach (['very_gentle' => __('Very gentle (one probe at a time, at most 10 a second; slowest)'), 'gentle' => __('Gentle (nmap polite timing -T2; default)'), 'normal' => __('Faster (nmap normal timing -T3, parallel, up to 200 a second; much more traffic)')] as $v => $l): ?>
                        <option value="<?= e($v) ?>" <?= ($site['agent_timing'] ?? 'gentle') === $v ? 'selected' : '' ?>><?= e($l) ?></option>
                        <?php endforeach; ?></select></div>
                <div><label class="form-label mb-0" for="poll-<?= $sid ?>"><?= e(__('Check-in every')) ?></label>
                    <select class="form-select form-select-sm" id="poll-<?= $sid ?>" name="poll_seconds">
                        <?php foreach (\Sentinel\Controllers\AgentController::POLL_CHOICES as $sec): ?>
                        <option value="<?= $sec ?>" <?= (int) ($site['agent_poll_seconds'] ?? 60) === $sec ? 'selected' : '' ?>><?= e($sec < 60 ? __('{n} seconds', ['n' => $sec]) : __('{n} minute(s)', ['n' => intdiv($sec, 60)])) ?></option>
                        <?php endforeach; ?></select></div>
                <button class="btn btn-sm btn-outline-primary" type="submit"><?= e(__('Save agent settings')) ?></button>
            </form>
            <div class="d-flex flex-wrap gap-2 mb-2">
                <form method="post" action="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/enrol')) ?>"><?= Csrf::field() ?><button class="btn btn-sm btn-outline-primary" type="submit"><i class="bi bi-key me-1" aria-hidden="true"></i><?= e(__('Create an enrolment code')) ?></button></form>
                <form method="post" data-confirm="<?= e(__('Start an internal scan of this site now? Its agent scans the authorised ranges at the site\'s pace.')) ?>" action="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/scan')) ?>" class="d-flex gap-2"><?= Csrf::field() ?>
                    <input class="form-control form-control-sm" name="reason" maxlength="300" placeholder="<?= e(__('Reason for a scan now')) ?>" aria-label="<?= e(__('Reason for a scan now')) ?>">
                    <button class="btn btn-sm btn-primary" type="submit"><i class="bi bi-radar me-1" aria-hidden="true"></i><?= e(__('Scan now')) ?></button></form>
            </div>
            <?php endif; ?>
            <?php if ($s['jobs'] !== []): ?>
            <ul class="list-unstyled small mb-0">
                <?php foreach ($s['jobs'] as $j): $sum = json_decode((string) ($j['summary'] ?? ''), true) ?: []; ?>
                <li>#<?= e($j['id']) ?> · <?= e($j['kind'] === 'full' ? __('full scan') : __('light sweep')) ?> · <?= e($jobLabel($j)) ?> · <?= e($j['created_at']) ?> UTC
                    <?php if (isset($sum['hosts'])): ?>· <?= e(__('{n} device(s), {m} new', ['n' => $sum['hosts'], 'm' => $sum['new_devices'] ?? 0])) ?><?php endif; ?>
                    <?php foreach ((array) ($sum['messages'] ?? []) as $msg): ?><div class="text-body-secondary ps-3"><?= e((string) $msg) ?></div><?php endforeach; ?></li>
                <?php endforeach; ?>
            </ul>
            <?php endif; ?>
            <?php // Active Directory checks: settings, where the password is (never the password: Sentinel doesn't have it), the DC certificate.
            $dir = $s['directory'];
            $siteAgent = null;
            foreach ($s['agents'] as $a) { if ($a['status'] === 'active') { $siteAgent = $a; break; } }
            $fp = static fn (string $h): string => implode(':', str_split(strtoupper($h), 2));
            ?>
            <div class="border-top mt-3 pt-3" id="directory-<?= $sid ?>">
                <h4 class="h6"><i class="bi bi-diagram-3 me-1" aria-hidden="true"></i><?= e(__('Active Directory checks')) ?></h4>
                <p class="small text-body-secondary mb-2"><?= e(__('With a read-only domain account, the agent reads the directory during each full scan for what attackers look for first: accounts that can be cracked offline, too many or stale admins, unconstrained delegation, an old krbtgt password, missing LAPS and LDAP signing. Nothing is changed in the directory.')) ?></p>
                <?php if ($dir !== null): ?>
                <ul class="list-unstyled small mb-2">
                    <li><strong><?= e(__('Domain:')) ?></strong> <?= e($dir['domain']) ?> · <?= e(__('domain controller')) ?> <span class="font-monospace"><?= e($dir['dc_ip']) ?></span> · <?= e(__('account')) ?> <span class="font-monospace"><?= e($dir['username']) ?></span></li>
                    <li><strong><?= e(__('Password:')) ?></strong>
                        <?php if ($dir['cred_state'] === 'held'): ?><span class="text-success"><i class="bi bi-shield-lock me-1" aria-hidden="true"></i><?= e(__('held by the agent (sealed), confirmed {t} UTC', ['t' => $dir['cred_confirmed_at']])) ?></span>
                        <?php elseif ($dir['cred_state'] === 'waiting'): ?><span class="text-warning"><?= e(__('sealed and waiting for the agent to collect it (set {t} UTC)', ['t' => $dir['cred_set_at']])) ?></span>
                        <?php elseif ($dir['cred_state'] === 'failed'): ?><span class="text-danger"><?= e(__('not with the agent: {why}', ['why' => $dir['cred_error']])) ?></span>
                        <?php else: ?><span class="text-body-secondary"><?= e(__('not set')) ?></span><?php endif; ?>
                        <span class="text-body-secondary">· <?= e(__('Sentinel never has the password: only the agent can open it.')) ?></span></li>
                    <li><strong><?= e(__('Domain controller certificate:')) ?></strong>
                        <?php if ($dir['cert_seen'] !== '' && $dir['cert_seen'] !== $dir['cert_trusted']): ?>
                            <span class="text-warning"><?= e($dir['cert_trusted'] === '' ? __('waiting for you to trust it') : __('CHANGED since you trusted it: the agent will not sign in until you trust the new one')) ?></span>
                            <div class="font-monospace text-break ps-3"><?= e($dir['cert_seen_subject']) ?><br>SHA-256 <?= e($fp($dir['cert_seen'])) ?></div>
                            <?php if ($isAdmin): ?>
                            <form method="post" action="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/directory/trust')) ?>" class="ps-3 mt-1" data-confirm="<?= e(__('Trust this certificate? Check that the fingerprint matches the domain controller\'s certificate first.')) ?>"><?= Csrf::field() ?>
                                <input type="hidden" name="fingerprint" value="<?= e($dir['cert_seen']) ?>">
                                <button class="btn btn-sm btn-outline-primary" type="submit"><i class="bi bi-patch-check me-1" aria-hidden="true"></i><?= e(__('Trust this certificate')) ?></button></form>
                            <?php endif; ?>
                        <?php elseif ($dir['cert_trusted'] !== ''): ?><span class="text-success"><?= e(__('trusted')) ?></span> <span class="font-monospace text-body-secondary small"><?= e(substr($fp($dir['cert_trusted']), 0, 23)) ?>…</span>
                        <?php else: ?><span class="text-body-secondary"><?= e(__('not seen yet: the agent fetches it at its next full scan (it does not sign in before you trust it).')) ?></span><?php endif; ?></li>
                    <li><strong><?= e(__('Last directory read:')) ?></strong>
                        <?= e($dir['checked_at'] !== null ? __('{t} UTC', ['t' => $dir['checked_at']]) : __('not yet')) ?>
                        <?php if ($dir['last_error'] !== ''): ?><div class="text-danger ps-3"><?= e($dir['last_error']) ?> <?= e($dir['last_attempt_at'] !== null ? '(' . $dir['last_attempt_at'] . ' UTC)' : '') ?></div><?php endif; ?></li>
                </ul>
                <?php endif; ?>
                <?php if ($isAdmin): ?>
                <details><summary class="small"><?= e($dir === null ? __('Set up Active Directory checks') : __('Change settings or replace the password')) ?></summary>
                <?php if ($siteAgent === null): ?>
                    <p class="small text-body-secondary mt-2"><?= e(__('Enrol an agent for this site first: the password is sealed for that agent.')) ?></p>
                <?php elseif ((string) ($siteAgent['box_key_pending'] ?? '') !== ''): ?>
                    <p class="small text-warning mt-2"><?= e(__('The agent reported a new key. Approve it (above) before setting a password: nothing is sealed to an unapproved key.')) ?></p>
                <?php else: $nonce = bin2hex(random_bytes(16)); ?>
                <form method="post" action="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/directory')) ?>" class="row g-2 mt-1 small" autocomplete="off"
                      data-agent-seal data-agent-key="<?= e((string) $siteAgent['box_public_key']) ?>"
                      data-aad-prefix="<?= e(\Sentinel\AgentClient\AgentKey::directoryAad((int) $siteAgent['id'], $nonce, '')) ?>"
                      data-insecure-text="<?= e(__('Passwords can only be sealed on an HTTPS page. Open Sentinel through its https:// address to set or replace the password.')) ?>"
                      data-missing-text="<?= e(__('Enter the account name too.')) ?>"
                      data-failed-text="<?= e(__('The password could not be sealed in your browser. Nothing was sent.')) ?>"
                      data-nokey-text="<?= e(__('This agent is too old to receive passwords: upgrade it first.')) ?>"><?= Csrf::field() ?>
                    <input type="hidden" name="sealed" value=""><input type="hidden" name="nonce" value="<?= e($nonce) ?>"><input type="hidden" name="agent_id" value="<?= (int) $siteAgent['id'] ?>">
                    <input type="hidden" name="seal_js" value="0">
                    <div class="col-md-4"><label class="form-label" for="dir-domain-<?= $sid ?>"><?= e(__('Domain')) ?></label>
                        <input class="form-control form-control-sm" id="dir-domain-<?= $sid ?>" name="domain" maxlength="253" required placeholder="corp.example" value="<?= e($dir['domain'] ?? '') ?>"></div>
                    <div class="col-md-3"><label class="form-label" for="dir-dc-<?= $sid ?>"><?= e(__('Domain controller IP')) ?></label>
                        <input class="form-control form-control-sm font-monospace" id="dir-dc-<?= $sid ?>" name="dc_ip" maxlength="45" required placeholder="10.0.0.10" value="<?= e($dir['dc_ip'] ?? '') ?>"></div>
                    <div class="col-md-5"><label class="form-label" for="dir-user-<?= $sid ?>"><?= e(__('Read-only account')) ?></label>
                        <input class="form-control form-control-sm font-monospace" id="dir-user-<?= $sid ?>" name="username" maxlength="256" required placeholder="svc-sentinel@corp.example" value="<?= e($dir['username'] ?? '') ?>"></div>
                    <div class="col-md-7"><label class="form-label" for="dir-pass-<?= $sid ?>"><?= e($dir !== null && $dir['cred_state'] !== 'none' ? __('New password (leave empty to keep the current one)') : __('Password')) ?></label>
                        <input class="form-control form-control-sm" id="dir-pass-<?= $sid ?>" type="password" data-seal-password autocomplete="new-password">
                        <div class="form-text"><?= e(__('Sealed in your browser for this site\'s agent before it is sent. Sentinel only relays it and cannot read it; the agent keeps it sealed on the appliance.')) ?>
                            <?php if ((string) $siteAgent['box_public_key'] !== ''): ?><?= e(__('Agent key {fp}: it should match the agent\'s status output.', ['fp' => \Sentinel\AgentClient\AgentKey::fingerprint((string) $siteAgent['box_public_key'])])) ?><?php endif; ?></div></div>
                    <div class="col-md-5 d-flex align-items-end gap-2">
                        <button class="btn btn-sm btn-primary" type="submit"><i class="bi bi-lock me-1" aria-hidden="true"></i><?= e(__('Save')) ?></button></div>
                    <div class="col-12"><div class="alert alert-warning py-1 px-2 mb-0 d-none" data-seal-note role="status"></div></div>
                </form>
                <?php endif; ?>
                <?php if ($dir !== null): ?>
                <form method="post" action="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/directory/remove')) ?>" class="mt-2" data-confirm="<?= e(__('Turn off Active Directory checks for this site? The agent deletes the password.')) ?>"><?= Csrf::field() ?>
                    <button class="btn btn-sm btn-outline-danger" type="submit"><?= e(__('Turn off')) ?></button></form>
                <?php endif; ?>
                </details>
                <?php endif; ?>
            </div>
        </div>
        <?php endforeach; ?>
    </div>
</div>
<?php if ($isAdmin): ?><script src="<?= e(asset('js/agent-seal.js')) ?>"></script><?php endif; ?>

<?php
/**
 * A new one-time enrolment code (shown once; the page is not cached) with the full install steps: requirements, the
 * one-line install and the archive install (the code is typed at the prompt, never put on a command line), a private
 * CA, how to check it worked, and troubleshooting.
 * Expects: $client, $site, $code, $serverUrl, $releaseKeyFp ('' when none), $authorised (an internal authorisation is
 * valid today). Everything shown is escaped; the commands contain only the configured address (app.public_url).
 */
$server = $serverUrl !== '' ? $serverUrl : 'https://sentinel.example';
$oneLine = 'curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/install-agent.sh | sudo SENTINEL_SERVER=' . $server . ' bash';
$fromArchive = 'sudo ./install/agent-install.sh --server ' . $server;
$windows = '[Net.ServicePointManager]::SecurityProtocol = \'Tls12\'; & ([scriptblock]::Create((Invoke-RestMethod https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/install-agent.ps1))) -Server ' . $server;
$cid = (int) $client['id'];
/** A command in a box with a copy button (sentinel.js copies the text of the element named by data-copy). */
$cmd = static function (string $id, string $text): string {
    return '<div class="d-flex gap-2 align-items-start mt-1 mb-2"><pre class="bg-body-tertiary p-2 mb-0 flex-grow-1 text-wrap text-break"><code id="' . e($id) . '">' . e($text) . '</code></pre>'
        . '<button type="button" class="btn btn-sm btn-outline-secondary" data-copy="' . e($id) . '" data-copied="' . e(__('Copied')) . '"><i class="bi bi-clipboard me-1" aria-hidden="true"></i>' . e(__('Copy')) . '</button></div>';
};
?>
<div class="card">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Enroll an agent: {client}, {site}', ['client' => $client['name'], 'site' => $site['name']])) ?></h2></div>
    <div class="card-body">
        <div class="alert alert-warning"><i class="bi bi-exclamation-triangle me-1" aria-hidden="true"></i><?= e(__('This code is shown only once. It works once, within 24 hours, for this site only. Keep this page open until the agent shows up.')) ?></div>
        <?php if (!$authorised): ?>
        <div class="alert alert-info"><i class="bi bi-info-circle me-1" aria-hidden="true"></i><?= e(__('This site has no internal authorization valid today. The agent will enroll and check in, but it scans nothing until you record one (who at the client approved scanning, the dates and the networks).')) ?>
            <a href="<?= e(url('/clients/' . $cid . '/sites/' . (int) $site['id'] . '/internal-authorisations/new')) ?>"><?= e(__('Record an internal authorization')) ?></a></div>
        <?php endif; ?>
        <p class="mb-1"><?= e(__('Enrollment code')) ?></p>
        <div class="d-flex gap-2 align-items-center mb-4">
            <span class="h3 font-monospace mb-0" id="enrol-code"><?= e($code) ?></span>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-copy="enrol-code" data-copied="<?= e(__('Copied')) ?>"><i class="bi bi-clipboard me-1" aria-hidden="true"></i><?= e(__('Copy')) ?></button>
        </div>

        <h3 class="h6"><?= e(__('1. Prepare the agent host')) ?></h3>
        <ul class="small">
            <li><?= e(__('A small mini-PC or virtual machine that stays on: Debian 13 (recommended), Debian 12 or Ubuntu 24.04 LTS, freshly installed, 64-bit. 2 CPU cores, 2 GB of memory and 20 GB of disk are plenty.')) ?>
                <?= e(__('Or a Windows machine that stays on: Windows Server 2022 or 2025, or Windows 11 (64-bit).')) ?></li>
            <li><?= e(__('On the internal network it should scan: a VM needs a bridged network adapter (an external virtual switch), not NAT. Give it a fixed address or a DHCP reservation.')) ?></li>
            <li><?= e(__('Outbound HTTPS (port 443) to {server}, and to the Debian or Ubuntu package mirrors (and GitHub for the one-line install). No inbound firewall rule is needed: Sentinel never connects to the agent.', ['server' => $server])) ?></li>
            <li><?= e(__('A user that can run sudo. The installer adds PHP and nmap, its own unprivileged user and a locked-down service.')) ?></li>
        </ul>

        <h3 class="h6"><?= e(__('2. Install')) ?></h3>
        <p class="small mb-1"><strong><?= e(__('One-line install (the agent host can reach GitHub):')) ?></strong> <?= e(__('paste this into the agent host\'s shell; it asks for the enrollment code.')) ?></p>
        <?= $cmd('cmd-oneline', $oneLine) ?>
        <p class="small mb-1"><strong><?= e(__('Or from the release archive (no GitHub access needed):')) ?></strong> <?= e(__('copy the Sentinel release archive (the same file you installed Sentinel from) to the agent host, unpack it, and run in the unpacked folder (it asks for the enrollment code):')) ?></p>
        <?= $cmd('cmd-archive', $fromArchive) ?>
        <p class="small mb-1"><strong><?= e(__('Or on Windows:')) ?></strong> <?= e(__('paste this into PowerShell opened with Run as administrator; it asks for the enrollment code. It installs PHP and nmap (without Npcap: scans are TCP connect scans, slower than on Linux), and the agent as the "MSP Sentinel Agent" service running under its own low-privilege account.')) ?></p>
        <?= $cmd('cmd-windows', $windows) ?>
        <?php if ($serverUrl === ''): ?><div class="small text-warning mb-2"><?= e(__('Set app.public_url in the config so these commands show your address.')) ?></div><?php endif; ?>
        <p class="small"><?= e(__('The code is typed at the prompt, not put on the command line, so it stays out of the shell history. If Sentinel uses a certificate from a private certificate authority, copy the CA certificate (PEM) to the agent host and add SENTINEL_CA=/path/ca.pem after sudo (one-line install), --ca /path/ca.pem (archive install) or -Ca C:\path\ca.pem (Windows). Add --dry-run to the archive install to see every step first.')) ?></p>

        <h3 class="h6"><?= e(__('3. Check it worked')) ?></h3>
        <ul class="small">
            <li><?= e(__('The installer ends with "Enrolled as agent #…". The agent shows up on this client\'s Agents page within a minute, as online.')) ?></li>
            <?php if ($releaseKeyFp !== ''): ?>
            <li><?= e(__('The installer prints "Release key pinned from Sentinel: …". It must be {fp} (the release key on Administration → System): agents install only updates signed with it.', ['fp' => $releaseKeyFp])) ?></li>
            <?php else: ?>
            <li><?= e(__('No release key exists yet: create one on Administration → System, so this agent can be updated from Sentinel (it is offered at its next check-in).')) ?></li>
            <?php endif; ?>
            <li><?= e(__('On the agent host:')) ?> <code>systemctl status sentinel-agent</code> <?= e(__('(running), and')) ?> <code>journalctl -u sentinel-agent -e</code> <?= e(__('for its log.')) ?>
                <?= e(__('On Windows: the "MSP Sentinel Agent" service in services.msc, and its log in C:\ProgramData\MSP Sentinel Agent\logs.')) ?></li>
        </ul>

        <h3 class="h6"><?= e(__('If something goes wrong')) ?></h3>
        <ul class="small">
            <li><?= e(__('"Enrollment refused": the code was already used or is older than 24 hours. Create a new code and run the installer again.')) ?></li>
            <li><?= e(__('Cannot connect, or a certificate error: from the agent host, try curl -I {server}. Check DNS, the firewall\'s outbound rules and any proxy; with a private certificate authority, give its certificate as described above.', ['server' => $server])) ?></li>
            <li><?= e(__('Online but no scans: check the internal authorization, the scan window and the pause switches for the client and site. Scan now (with a reason) starts one at once.')) ?></li>
            <li><?= e(__('Diagnostics on the Agents page shows the agent\'s versions, disk, memory and clock difference without logging in to it.')) ?></li>
        </ul>
        <a class="btn btn-outline-secondary" href="<?= e(url('/clients/' . $cid . '/agents')) ?>"><?= e(__('Back to the client')) ?></a>
    </div>
</div>

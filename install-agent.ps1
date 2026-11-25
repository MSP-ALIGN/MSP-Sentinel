<#
.SYNOPSIS
  MSP Sentinel on-premises agent for Windows: install, upgrade or remove.

.DESCRIPTION
  For Windows Server 2022/2025 and Windows 11 (64-bit), run in an elevated PowerShell (Run as administrator). With a
  one-time enrollment code from the client's Agents page in Sentinel:

    [Net.ServicePointManager]::SecurityProtocol = 'Tls12'; & ([scriptblock]::Create((Invoke-RestMethod https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/install-agent.ps1))) -Server https://sentinel.example

  It asks for the code (typed hidden, passed on stdin, never on a command line). What it does:
  - checks Windows (64-bit; Server 2022/2025 or Windows 11) and that it runs as administrator;
  - installs the Microsoft Visual C++ runtime PHP needs, if missing (only when signed by Microsoft);
  - downloads PHP 8.4 (NTS x64) from windows.php.net and checks it against the SHA-256 windows.php.net publishes;
  - if nmap is missing, downloads it from nmap.org, checks it against nmap.org's published SHA-256 and its
    Authenticode signature, and installs it silently. That works where Npcap is already installed; otherwise the free
    nmap's bundled Npcap needs a click, so its setup window opens: click through and untick Npcap (the agent only uses
    unprivileged TCP connect scans). For an unattended install on such a machine, put nmap on first;
  - downloads the agent code (this repository) and WinSW (the service wrapper; SHA-256 pinned below);
  - puts code, PHP and WinSW in C:\Program Files\MSP Sentinel Agent (Administrators and SYSTEM can change it), and
    config, state, logs and update results in C:\ProgramData\MSP Sentinel Agent with tight permissions: the agent's
    service account (NT SERVICE\SentinelAgent, a virtual account without password or admin rights) reads its config
    and writes only its state and logs;
  - enrolls with the code (pins Sentinel's key, site and client, and the release key);
  - starts the "MSP Sentinel Agent" service and registers the "MSP Sentinel Agent Update" task (SYSTEM, every 5
    minutes), which installs updates only when signed with the pinned release key.

  -Upgrade      installs this script's code over the existing agent (keeps the enrollment).
  -Uninstall    removes the service, the task and the files (revoke the agent in Sentinel too).
  -ReleaseKey   gives the agent the release key by hand (after the key was replaced on Sentinel's System page).
  -Ca           a CA certificate (PEM file) when Sentinel uses a certificate from a private CA.

  Never run this from a folder other users can write to. Nothing here is sent anywhere but Sentinel, GitHub,
  windows.php.net, nmap.org and Microsoft's download servers.
#>
[CmdletBinding()]
param(
    [string]$Server = $env:SENTINEL_SERVER,
    [string]$Ca = '',
    [switch]$Upgrade,
    [switch]$Uninstall,
    [string]$ReleaseKey = '',
    [string]$Repo = 'MSP-ALIGN/MSP-Sentinel',
    [string]$Branch = 'main',
    [string]$NmapVersion = '7.95'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'  # much faster downloads in Windows PowerShell 5.1

# Where everything goes.
$Root      = Join-Path $env:ProgramFiles 'MSP Sentinel Agent'
$App       = Join-Path $Root 'app'
$PhpDir    = Join-Path $Root 'php'
$Php       = Join-Path $PhpDir 'php.exe'
$PhpIni    = Join-Path $PhpDir 'php.ini'
$SvcDir    = Join-Path $Root 'service'
$Data      = Join-Path $env:ProgramData 'MSP Sentinel Agent'
$ConfDir   = Join-Path $Data 'config'
$StateDir  = Join-Path $Data 'state'
$UpdateDir = Join-Path $Data 'update'
$LogDir    = Join-Path $Data 'logs'
$Service   = 'SentinelAgent'
$Account   = 'NT SERVICE\SentinelAgent'
$TaskName  = 'MSP Sentinel Agent Update'

# WinSW 2.12.0 (MIT licence), the .NET Framework 4.6.1 build (.NET Framework 4.8 ships with Windows Server 2022/2025 and
# Windows 11; unlike the self-contained build it extracts nothing to a temp folder at start): pinned by SHA-256.
$WinswUrl    = 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW.NET461.exe'
$WinswSha256 = 'b5066b7bbdfba1293e5d15cda3caaea88fbeab35bd5b38c41c913d492aadfc4f'
$Launcher    = Join-Path $Root 'agent-update-launcher.php'

function Say([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }
# Failures throw (never `exit`: run as a script block, exit would close the administrator's PowerShell window).
function Fail([string]$Text) { throw $Text }

function Assert-Admin {
    $id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'Run this in an elevated PowerShell (Run as administrator).' }
}

function Assert-Windows {
    if (-not [Environment]::Is64BitOperatingSystem) { Fail 'A 64-bit Windows is needed.' }
    $os = Get-CimInstance Win32_OperatingSystem
    $build = [int]$os.BuildNumber
    # ProductType 1 = workstation (Windows 11 from build 22000); 2/3 = server (Server 2022 from build 20348).
    if (($os.ProductType -eq 1 -and $build -lt 22000) -or ($os.ProductType -ne 1 -and $build -lt 20348)) {
        Fail "Supported: Windows Server 2022/2025 and Windows 11 (found $($os.Caption), build $build)."
    }
}

# A folder an unprivileged account could have turned into a junction (mount point) or symbolic link: never act through it.
function Test-Redirected([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    return [bool]((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)
}
function Assert-NotRedirected {
    foreach ($d in $Data, $ConfDir, $StateDir, $UpdateDir, $LogDir) {
        if (Test-Redirected $d) { Fail "$d is a link or junction, not a folder: refusing to touch it. Inspect this machine." }
    }
}
# Delete a folder tree without following junctions or links inside it (rmdir /s removes links, never their targets).
function Remove-Tree([string]$Path) {
    if (Test-Path -LiteralPath $Path) { & cmd.exe /d /c rmdir /s /q "`"$Path`"" | Out-Null }
}

function Get-Download([string]$Url, [string]$Dest) {
    Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
}

function Assert-Sha256([string]$File, [string]$Expected) {
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $File).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) { Fail "$([IO.Path]::GetFileName($File)) does not match its published SHA-256: refusing to use it." }
}

function Assert-Signed([string]$File, [string]$SignerPattern) {
    $sig = Get-AuthenticodeSignature -LiteralPath $File
    if ($sig.Status -ne 'Valid' -or $null -eq $sig.SignerCertificate -or $sig.SignerCertificate.Subject -notmatch $SignerPattern) {
        Fail "$([IO.Path]::GetFileName($File)) is not validly signed by the expected publisher: refusing to run it."
    }
}

# A private temporary folder (only Administrators and SYSTEM), removed at the end.
$Tmp = Join-Path $env:TEMP ('sentinel-agent-' + [Guid]::NewGuid().ToString('N'))
function New-PrivateDir([string]$Path) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
}

function Install-VcRuntime {
    # PHP 8.4 (built with Visual Studio 2022) needs the 14.30 runtime or later.
    $rt = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' -ErrorAction SilentlyContinue
    if ($rt -and ($rt.PSObject.Properties.Name -contains 'Installed') -and $rt.Installed -eq 1 -and ($rt.PSObject.Properties.Name -contains 'Minor') -and [int]$rt.Minor -ge 30) { return }
    Say 'Installing the Microsoft Visual C++ runtime (needed by PHP)'
    $exe = Join-Path $Tmp 'vc_redist.x64.exe'
    Get-Download 'https://aka.ms/vs/17/release/vc_redist.x64.exe' $exe
    Assert-Signed $exe 'O=Microsoft Corporation'
    $p = Start-Process -FilePath $exe -ArgumentList '/install', '/quiet', '/norestart' -Wait -PassThru
    if ($p.ExitCode -notin 0, 3010, 1638) { Fail "The Visual C++ runtime did not install (exit $($p.ExitCode))." }
}

function Install-Php {
    Say 'Installing PHP 8.4 (NTS x64) from windows.php.net'
    $rel = Invoke-RestMethod -Uri 'https://windows.php.net/downloads/releases/releases.json' -UseBasicParsing
    $branch = $rel.'8.4'
    if ($null -eq $branch) { Fail 'windows.php.net lists no PHP 8.4 release.' }
    $build = $branch.PSObject.Properties | Where-Object { $_.Name -like 'nts-vs*-x64' } | Select-Object -First 1
    if ($null -eq $build) { Fail 'windows.php.net lists no PHP 8.4 NTS x64 build.' }
    $zipInfo = $build.Value.zip
    if ($zipInfo.path -notmatch '^php-8\.4\.\d+-nts-Win32-vs\d+-x64\.zip$' -or $zipInfo.sha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail 'Unexpected PHP release listing.' }
    $zip = Join-Path $Tmp $zipInfo.path
    Get-Download ('https://windows.php.net/downloads/releases/' + $zipInfo.path) $zip
    Assert-Sha256 $zip $zipInfo.sha256
    Remove-Tree $PhpDir
    Expand-Archive -LiteralPath $zip -DestinationPath $PhpDir
    # Only what the agent needs; no php.ini is read from anywhere else (the service and the task pass -c).
    @(
        '; MSP Sentinel agent (written by install-agent.ps1)'
        "extension_dir = `"$PhpDir\ext`""
        'extension = curl'
        'extension = mbstring'
        'extension = openssl'
        'extension = sodium'
        'display_errors = Off'
        'log_errors = On'
        'memory_limit = 256M'
        'date.timezone = UTC'
    ) | Set-Content -LiteralPath $PhpIni -Encoding ASCII
    $v = & $Php -c $PhpIni -r 'echo PHP_VERSION;'
    Say "PHP $v installed"
}

# Runs nmap's setup silently (/S) for at most 5 minutes. Returns nmap.exe's path when nmap was installed, or $null when
# the setup did not finish on its own (usually Npcap's installer waiting for a click): then the setup and everything
# it started are stopped, so the setup window can be used next without two installers running at once.
function Install-NmapSilently([string]$exe) {
    Say 'Trying a silent nmap install (it finishes on its own when Npcap is already installed)'
    $p = Start-Process -FilePath $exe -ArgumentList '/S' -PassThru
    $null = $p.Handle  # keep the process handle, or ExitCode reads as empty after WaitForExit
    $finished = $p.WaitForExit(300000)
    if (-not $finished) {
        Stop-ProcessTree $p.Id
    }
    $found = @("${env:ProgramFiles(x86)}\Nmap\nmap.exe", "$env:ProgramFiles\Nmap\nmap.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($found) {
        # Installed, even if Npcap's part was stopped: nmap must also run (the agent never needs Npcap).
        & $found --version *> $null
        if ($LASTEXITCODE -eq 0) {
            if ($finished) { Say "nmap installed silently: $found" } else { Say "nmap installed silently (Npcap's part was skipped): $found" }
            return $found
        }
    }
    if ($finished) {
        Say "The silent nmap install did not leave a working nmap (exit $($p.ExitCode)); using the setup window instead."
    } else {
        Say 'The silent nmap install waited for a click (Npcap); it was stopped. Using the setup window instead.'
    }
    return $null
}

# Stops a process and every process it started (children first), e.g. nmap's setup and the Npcap installer it runs.
function Stop-ProcessTree([int]$id) {
    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $id" -ErrorAction SilentlyContinue)
    foreach ($c in $children) { Stop-ProcessTree ([int]$c.ProcessId) }
    Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
}

function Install-Nmap {
    $existing = @("${env:ProgramFiles(x86)}\Nmap\nmap.exe", "$env:ProgramFiles\Nmap\nmap.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($existing) { Say "nmap found: $existing"; return $existing }
    Say "Installing nmap $NmapVersion from nmap.org (without Npcap)"
    if ($NmapVersion -notmatch '^\d+\.\d+$') { Fail '-NmapVersion must look like 7.95.' }
    $name = "nmap-$NmapVersion-setup.exe"
    $exe = Join-Path $Tmp $name
    Get-Download "https://nmap.org/dist/$name" $exe
    # nmap.org's digest file: "... SHA256 = 0B1C 2D3E ..." (hex in groups, possibly over two lines).
    $digest = (Invoke-WebRequest -Uri "https://nmap.org/dist/sigs/$name.digest.txt" -UseBasicParsing).Content
    if ($digest -notmatch '(?s)SHA256\s*=\s*([0-9A-Fa-f\s]+?)(?:\r?\n\S|\z)') { Fail 'nmap.org published no SHA-256 for that file.' }
    $sha = ($Matches[1] -replace '\s', '')
    if ($sha.Length -ne 64) { Fail 'nmap.org published no SHA-256 for that file.' }
    Assert-Sha256 $exe $sha
    Assert-Signed $exe 'Insecure\.Com|Nmap Software'
    # 1.56.2: try the silent install first. nmap itself installs silently with /S; only the bundled Npcap (free
    # edition) can't, and waits for a click. So it finishes on its own where Npcap is already installed (or not
    # needed), and otherwise is stopped after a few minutes and the setup window below is used instead.
    $silent = Install-NmapSilently $exe
    if ($silent) { return $silent }
    # Not silent: someone clicks through the setup window. Nobody can do that in a session without a desktop (an RMM
    # tool running this as SYSTEM): stop at once and say to install nmap first.
    if (-not [Environment]::UserInteractive) {
        Fail 'nmap is not installed, and its installer needs someone at the screen. Install nmap from nmap.org first (untick Npcap), then run this again.'
    }
    Say 'The nmap setup window opens now: click through it and UNTICK "Npcap" on the components page (the agent does not need it).'
    $p = Start-Process -FilePath $exe -PassThru
    $null = $p.Handle  # keep the process handle, or ExitCode reads as empty after WaitForExit
    if (-not $p.WaitForExit(1800000)) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        Fail "nmap's setup was not finished within 30 minutes. Install nmap from nmap.org by hand (untick Npcap), then run this again."
    }
    $found = @("${env:ProgramFiles(x86)}\Nmap\nmap.exe", "$env:ProgramFiles\Nmap\nmap.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $found -or ($null -ne $p.ExitCode -and $p.ExitCode -ne 0)) { Fail "nmap did not install (exit $($p.ExitCode))." }
    return $found
}

function Install-Code {
    Say "Downloading the agent ($Repo, $Branch)"
    if ($Repo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or $Branch -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]{0,59}$' -or $Branch -like '*..*') { Fail 'Invalid -Repo or -Branch.' }
    $zip = Join-Path $Tmp 'agent.zip'
    Get-Download "https://github.com/$Repo/archive/refs/heads/$Branch.zip" $zip
    $src = Join-Path $Tmp 'src'
    Expand-Archive -LiteralPath $zip -DestinationPath $src
    $top = Get-ChildItem -LiteralPath $src -Directory | Select-Object -First 1
    if (-not $top -or -not (Test-Path (Join-Path $top.FullName 'bin\sentinel-agent.php'))) { Fail 'The download is not an MSP Sentinel release.' }
    New-Item -ItemType Directory -Force -Path $App | Out-Null
    # Mirror the release into the code folder, without what the agent doesn't need (and never config or data).
    & robocopy.exe $top.FullName $App /MIR /XD config storage dist tests .github /XF .gitignore .gitattributes /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { Fail "Copying the agent code failed (robocopy $LASTEXITCODE)." }
    # The update task's launcher lives outside app\ so the task can swap app\ (see agent-update-launcher.php).
    Copy-Item -LiteralPath (Join-Path $App 'install\windows\agent-update-launcher.php') -Destination $Launcher -Force
    # The update task's code runs from updater\, a copy remote updates never change (1.35): code from a new release
    # never runs as SYSTEM. Refreshed here from the release installed by hand.
    $Updater = Join-Path $Root 'updater'
    if (Test-Path -LiteralPath $Updater) { Remove-Item -LiteralPath $Updater -Recurse -Force }
    & robocopy.exe (Join-Path $App 'src') (Join-Path $Updater 'src') /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { Fail "Copying the update code failed (robocopy $LASTEXITCODE)." }
    New-Item -ItemType Directory -Force -Path (Join-Path $Updater 'bin') | Out-Null
    Copy-Item -LiteralPath (Join-Path $App 'bin\agent-update-task.php') -Destination (Join-Path $Updater 'bin\agent-update-task.php') -Force
    return (Get-Content -LiteralPath (Join-Path $App 'VERSION') -Raw).Trim()
}

function Install-Winsw {
    Say 'Installing the service wrapper (WinSW 2.12.0)'
    New-Item -ItemType Directory -Force -Path $SvcDir | Out-Null
    $exe = Join-Path $Tmp 'WinSW.NET461.exe'
    Get-Download $WinswUrl $exe
    Assert-Sha256 $exe $WinswSha256
    Copy-Item -LiteralPath $exe -Destination (Join-Path $SvcDir "$Service.exe") -Force
    $esc = { param($s) [Security.SecurityElement]::Escape($s) }
    $svcArgs = "-c `"$PhpIni`" `"$App\bin\sentinel-agent.php`" run --config `"$ConfDir\agent.json`""
    @"
<service>
  <id>$Service</id>
  <name>MSP Sentinel Agent</name>
  <description>MSP Sentinel on-premises agent: scans the approved internal networks and reports to Sentinel.</description>
  <executable>$(& $esc $Php)</executable>
  <arguments>$(& $esc $svcArgs)</arguments>
  <workingdirectory>$(& $esc $StateDir)</workingdirectory>
  <startmode>Automatic</startmode>
  <delayedAutoStart>true</delayedAutoStart>
  <stoptimeout>30 sec</stoptimeout>
  <onfailure action="restart" delay="10 sec"/>
  <onfailure action="restart" delay="30 sec"/>
  <onfailure action="restart" delay="60 sec"/>
  <resetfailure>1 hour</resetfailure>
  <logpath>$(& $esc $LogDir)</logpath>
  <log mode="roll-by-size"><sizeThreshold>10240</sizeThreshold><keepFiles>5</keepFiles></log>
</service>
"@ | Set-Content -LiteralPath (Join-Path $SvcDir "$Service.xml") -Encoding UTF8
}

function Invoke-Icacls {
    & icacls.exe @args | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "Setting folder permissions failed (icacls $($args -join ' '))." }
}

# SIDs of the only accounts that may own or change the agent's protected folders.
$TrustedSids = @('S-1-5-18', 'S-1-5-32-544')  # SYSTEM, Administrators

function Set-Folders {
    # A fresh install starts from a folder it created itself. A local user can create folders in ProgramData (and would
    # own them), so: remove whatever is there (rmdir /s: links removed, never followed), then CREATE it (no -Force:
    # if someone recreated it in between, this fails), then replace its whole permission list at once (protected: no
    # inheritance; SYSTEM and Administrators only; owner Administrators) and check that nothing else got in.
    Remove-Tree $Data
    if (Test-Path -LiteralPath $Data) { Fail "$Data could not be removed: inspect this machine." }
    New-Item -ItemType Directory -Path $Data | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $admins = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    $acl.SetOwner($admins)
    foreach ($sid in $TrustedSids) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule (New-Object Security.Principal.SecurityIdentifier $sid),
            'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Data -AclObject $acl
    # Nothing may have been created inside in the moment before the permissions were set.
    if (@(Get-ChildItem -LiteralPath $Data -Force).Count -ne 0) { Fail "Something was created in $Data during the install: inspect this machine." }
    Assert-Protected $Data
    foreach ($d in $ConfDir, $StateDir, $UpdateDir, $LogDir) { New-Item -ItemType Directory -Path $d | Out-Null }
}

# A folder only SYSTEM and Administrators own and can change (read access for others is fine), and not a link.
function Assert-Protected([string]$Path) {
    if (Test-Redirected $Path) { Fail "$Path is a link or junction: refusing to use it. Inspect this machine." }
    $acl = Get-Acl -LiteralPath $Path
    $owner = (New-Object Security.Principal.NTAccount $acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($TrustedSids -notcontains $owner) { Fail "$Path is owned by $($acl.Owner), not Administrators: refusing to use it. Inspect this machine." }
    $write = [Security.AccessControl.FileSystemRights]'WriteData,AppendData,WriteExtendedAttributes,WriteAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($r.AccessControlType -eq 'Allow' -and ($r.FileSystemRights -band $write) -and $TrustedSids -notcontains $r.IdentityReference.Value) {
            Fail "$Path can be changed by $($r.IdentityReference.Value): refusing to use it. Inspect this machine."
        }
    }
}

function Set-AgentAccess {
    # Only on a fresh install, when the folders are new and empty (on -Upgrade the permissions are already set, and the
    # agent could have put junctions in its own folders that icacls would follow). The service account (exists once
    # the service is registered): reads config and update results, writes state and logs.
    Assert-NotRedirected
    Invoke-Icacls $Data /grant "${Account}:(RX)"
    Invoke-Icacls $ConfDir /grant "${Account}:(OI)(CI)(RX)"
    Invoke-Icacls $UpdateDir /grant "${Account}:(OI)(CI)(RX)"
    Invoke-Icacls $StateDir /grant "${Account}:(OI)(CI)(M)"
    Invoke-Icacls $LogDir /grant "${Account}:(OI)(CI)(M)"
}

function Register-Service {
    $wrapper = Join-Path $SvcDir "$Service.exe"
    if (-not (Get-Service -Name $Service -ErrorAction SilentlyContinue)) {
        & $wrapper install | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'Registering the service failed.' }
    }
    # Run as its own virtual account (no password, no admin rights).
    # Run as its own virtual account, and start automatically (also resets a start mode an interrupted update left).
    & sc.exe config $Service obj= $Account start= delayed-auto | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 'Setting the service account failed.' }
    # Only the privileges it needs: every service gets "Impersonate a client" by default, which known tools turn into
    # SYSTEM. With a required-privileges list, the service process gets these two and nothing else.
    & sc.exe privs $Service 'SeChangeNotifyPrivilege/SeCreateGlobalPrivilege' | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 'Limiting the service''s privileges failed.' }
}

function Register-UpdateTask {
    $action = New-ScheduledTaskAction -Execute $Php -Argument "-c `"$PhpIni`" `"$Launcher`"" -WorkingDirectory $UpdateDir
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew -StartWhenAvailable
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}

function Set-ReleaseKey([string]$Key) {
    if ($Key -notmatch '^[A-Za-z0-9+/]{43}=$') { Fail '-ReleaseKey must be the base64 public key shown on Sentinel''s System page.' }
    Set-Content -LiteralPath (Join-Path $ConfDir 'release-key.pub') -Value $Key -Encoding ASCII
    Say 'Release key pinned from -ReleaseKey.'
}

# ---------------------------------------------------------------------------------------------------------------------
$script:RestartService = $false
try {
    Assert-Admin

    if ($Uninstall) {
        Say 'Removing the MSP Sentinel agent'
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        if (Get-Service -Name $Service -ErrorAction SilentlyContinue) {
            Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
            & (Join-Path $SvcDir "$Service.exe") uninstall | Out-Null
        }
        # rmdir /s removes links and junctions the agent may have made in its folders, never what they point to.
        foreach ($d in $Root, $Data) { Remove-Tree $d }
        Say 'Done. Revoke the agent on the client''s Agents page in Sentinel too. PHP''s runtime and nmap stay installed.'
        return
    }

    Assert-Windows
    New-PrivateDir $Tmp

    if ($Upgrade) {
        if (-not (Test-Path (Join-Path $ConfDir 'agent.json'))) { Fail 'No enrolled agent found. Install without -Upgrade first.' }
        Say 'Upgrading the agent (the enrollment is kept)'
        # Only an agent this script installed: its service exists and its protected folders are still only
        # Administrators' (a folder a local user made, or changed, is never trusted).
        if (-not (Get-Service -Name $Service -ErrorAction SilentlyContinue)) { Fail 'No agent service found: install without -Upgrade (after -Uninstall).' }
        Assert-NotRedirected
        foreach ($d in $Data, $ConfDir, $UpdateDir) { Assert-Protected $d }
        # The update task must not swap app\ while this copies it: pause it and wait for a running one to finish.
        Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
        for ($i = 0; $i -lt 120 -and (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Where-Object State -eq 'Running'); $i++) { Start-Sleep -Seconds 5 }
        $script:RestartService = $true
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Where-Object State -eq 'Running') { Fail 'The update task is still running after 10 minutes: try again later.' }
        Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
        Install-VcRuntime
        Install-Php
        $version = Install-Code
        Install-Winsw
        Register-Service
        if ($ReleaseKey) { Set-ReleaseKey $ReleaseKey }
        Register-UpdateTask
        Start-Service -Name $Service
        $script:RestartService = $false
        Say "Done: agent $version is running."
        return
    }

    if (Test-Path (Join-Path $ConfDir 'agent.json')) { Fail 'This machine already has an enrolled agent. Use -Upgrade, or -Uninstall first.' }
    if ($Server -notmatch '^https://[^\s/]+') {
        $Server = Read-Host 'Sentinel address (https://...)'
        if ($Server -notmatch '^https://[^\s/]+') { Fail 'The Sentinel address must start with https://' }
    }
    $Server = $Server.TrimEnd('/')
    $secure = Read-Host 'One-time enrollment code' -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $code = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if ($code -notmatch '^SNE(-[A-Z2-9]{5}){4}$') { Fail 'That is not an enrollment code (SNE-XXXXX-XXXXX-XXXXX-XXXXX).' }

    Install-VcRuntime
    Install-Php
    $nmap = Install-Nmap
    $version = Install-Code
    Set-Folders
    $caArg = @()
    if ($Ca) {
        if (-not (Test-Path -LiteralPath $Ca -PathType Leaf)) { Fail '-Ca must be a CA certificate file (PEM).' }
        Copy-Item -LiteralPath $Ca -Destination (Join-Path $ConfDir 'ca.pem') -Force
        $caArg = @('--ca', (Join-Path $ConfDir 'ca.pem'))
    }
    if ($ReleaseKey) { Set-ReleaseKey $ReleaseKey }

    Say 'Enrolling with Sentinel (pins its signing key, site and client)'
    $enrol = @('-c', $PhpIni, "$App\bin\sentinel-agent.php", 'enroll', '--server', $Server, '--code-stdin', '--config', "$ConfDir\agent.json", '--state-dir', $StateDir, '--nmap', $nmap) + $caArg
    $code | & $Php @enrol
    $code = $null
    if ($LASTEXITCODE -ne 0) { Fail 'Enrollment failed (see above). Create a new code if this one was used or expired.' }

    Install-Winsw
    Register-Service
    Set-AgentAccess
    Register-UpdateTask
    Start-Service -Name $Service
    Say "Done: agent $version is running as $Account. It appears on the client's Agents page within a minute."
    Say "Logs: $LogDir. Remove: run this script with -Uninstall."
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    $global:LASTEXITCODE = 1
} finally {
    # An -Upgrade that failed half-way: don't leave the agent stopped or its update task paused.
    if ($script:RestartService) {
        Start-Service -Name $Service -ErrorAction SilentlyContinue
        Enable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
    }
    Remove-Tree $Tmp
}

<#
.SYNOPSIS
  MSP Sentinel: create (or renew) the Microsoft Entra app for "Sign in with Microsoft" and send its details to Sentinel.

.DESCRIPTION
  In Sentinel, open Administration > Integrations > Sign in with Microsoft and click "Create setup code". Then, on any
  Windows PC, in PowerShell (no admin rights on the PC needed):

    [Net.ServicePointManager]::SecurityProtocol = 'Tls12'; & ([scriptblock]::Create((Invoke-RestMethod https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/entra-sso-setup.ps1))) -Server https://sentinel.example

  What it does:
  - installs the Microsoft Graph PowerShell authentication module for you (current user) if it is missing;
  - signs you in at Microsoft (browser window): use an Entra admin who can register apps and grant consent
    (Application Administrator, Cloud Application Administrator or Global Administrator);
  - creates the app registration "MSP Sentinel (<address>)", single tenant, with Sentinel's redirect address, or
    updates the one this script made before (found by its tag);
  - adds the optional ID-token claim auth_time, so Sentinel can see when Microsoft MFA happened (and skip its own code
    only then);
  - asks only for sign-in permissions (openid, profile, email: no access to mail, files or anything else) and grants
    them for the organisation, so users aren't asked to consent;
  - adds a client secret valid for 12 months (-SecretMonths) and sends tenant ID, client ID and secret to Sentinel with
    the one-time setup code (typed hidden). The secret is never shown or written to disk;
  - after Sentinel has saved it, removes older secrets this script made for the app (so a renewal leaves one).

  Nothing is sent anywhere but Microsoft (sign-in and Microsoft Graph) and your Sentinel.
#>
[CmdletBinding()]
param(
    [string]$Server = '',
    [ValidateRange(1, 24)][int]$SecretMonths = 12
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

# Microsoft Graph and its delegated sign-in permissions (well-known IDs, the same in every tenant).
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$SignInScopes = @(
    @{ id = '37f7f235-527c-4136-accd-4a02d197296e'; type = 'Scope' }  # openid
    @{ id = '14dad69e-099b-42c9-810b-d002981feec1'; type = 'Scope' }  # profile
    @{ id = '64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0'; type = 'Scope' }  # email
)
$SecretPrefix = 'MSP Sentinel sign-in'

function Say([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }
# Failures throw (never `exit`: run as a script block, exit would close the PowerShell window).
function Fail([string]$Text) { throw $Text }

function Invoke-Graph([string]$Method, [string]$Path, $Body = $null) {
    $uri = 'https://graph.microsoft.com/v1.0' + $Path
    if ($null -eq $Body) {
        return Invoke-MgGraphRequest -Method $Method -Uri $uri -OutputType HashTable
    }
    return Invoke-MgGraphRequest -Method $Method -Uri $uri -Body ($Body | ConvertTo-Json -Depth 8) -ContentType 'application/json' -OutputType HashTable
}

function Get-First([string]$Path) {
    $r = Invoke-Graph 'GET' $Path
    if ($r.ContainsKey('value') -and @($r['value']).Count -gt 0) { return @($r['value'])[0] }
    return $null
}

function Enc([string]$Text) { return [Uri]::EscapeDataString($Text) }

$connected = $false
$newKeyId = $null
$appObjectId = $null
try {
    # Sentinel's address (its app.public_url, a sub-folder allowed): the redirect address is built from it exactly as
    # Sentinel does, and Sentinel refuses the details if they differ.
    $Server = $Server.Trim().TrimEnd('/')
    if ($Server -notmatch '^https://') {
        $Server = (Read-Host "Sentinel's address (https://..., as shown on its Integrations page)").Trim().TrimEnd('/')
    }
    if ($Server -notmatch '^https://[A-Za-z0-9.-]+(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?$') { Fail 'The Sentinel address must look like https://sentinel.example (as shown on its Integrations page).' }
    $Redirect = "$Server/login/sso/callback"
    $HostName = (([Uri]$Server).Authority + ([Uri]$Server).AbsolutePath.TrimEnd('/')).ToLowerInvariant()
    $Tag = "msp-sentinel-sso:$HostName"

    $secure = Read-Host 'One-time setup code from Sentinel' -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $code = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    $code = $code.Trim().ToUpperInvariant()
    if ($code -notmatch '^SSO(-[A-HJ-NP-Z2-9]{5}){4}$') { Fail 'That is not a setup code (SSO-XXXXX-XXXXX-XXXXX-XXXXX). Create one on Sentinel''s Integrations page.' }

    # Microsoft Graph PowerShell: only the authentication module is needed (all calls are plain Graph requests).
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Say 'Installing the Microsoft Graph PowerShell authentication module (for the current user, from the PowerShell Gallery)'
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
    }
    Import-Module Microsoft.Graph.Authentication

    Say 'Signing in at Microsoft (a browser window opens): use an Entra admin who can register apps'
    # Process scope: the token is not saved on this PC after the window closes.
    Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All' -ContextScope Process -NoWelcome
    $connected = $true
    $tenant = (Get-MgContext).TenantId
    if (-not $tenant) { Fail 'Microsoft did not say which tenant you signed in to.' }
    # Show which tenant this is and ask, so an MSP signed in to the wrong one stops here (Sentinel refuses another
    # tenant too, unless the setup code allows switching).
    $orgName = ''
    try { $org = Get-First '/organization?$select=displayName'; if ($null -ne $org) { $orgName = [string]$org['displayName'] } } catch { $orgName = '' }
    Say "Signed in to tenant $tenant $(if ($orgName) { "($orgName)" })"
    $ok = Read-Host "Create or update the MSP Sentinel app in this tenant? (y/N)"
    if ($ok -notmatch '^(y|yes)$') { Fail 'Stopped: nothing was changed in Microsoft Entra or Sentinel.' }

    # The app: the one this script made before for this Sentinel (by its tag), else a new one.
    $app = Get-First ('/applications?$filter=' + (Enc "tags/any(t:t eq '$Tag')") + '&$select=id,appId,displayName,web,optionalClaims')
    if ($null -eq $app) {
        Say "Creating the app registration ""MSP Sentinel ($HostName)"""
        $app = Invoke-Graph 'POST' '/applications' @{
            displayName            = "MSP Sentinel ($HostName)"
            signInAudience         = 'AzureADMyOrg'
            tags                   = @($Tag)
            web                    = @{ redirectUris = @($Redirect); implicitGrantSettings = @{ enableIdTokenIssuance = $false; enableAccessTokenIssuance = $false } }
            requiredResourceAccess = @(@{ resourceAppId = $GraphAppId; resourceAccess = $SignInScopes })
            optionalClaims         = @{ idToken = @(@{ name = 'auth_time'; essential = $false }) }
        }
    } else {
        Say "Updating the existing app registration ""$($app['displayName'])"""
        # PATCH replaces the whole "web" object: send back what is there (logout and home page addresses, implicit grant
        # settings), with Sentinel's redirect address added.
        $web = $app['web']
        if ($null -eq $web) { $web = @{} }
        $uris = @($web['redirectUris'] | Where-Object { $_ })
        if ($uris -notcontains $Redirect) { $uris += $Redirect }
        $web['redirectUris'] = @($uris)
        if ($web.ContainsKey('redirectUriSettings')) { $web.Remove('redirectUriSettings') }  # read-only, follows redirectUris
        # Keep any optional claims someone added; make sure auth_time is among the ID token's.
        $claims = $app['optionalClaims']
        if ($null -eq $claims) { $claims = @{ idToken = @(); accessToken = @(); saml2Token = @() } }
        $idClaims = @($claims['idToken'] | Where-Object { $null -ne $_ })
        if (-not ($idClaims | Where-Object { $_['name'] -eq 'auth_time' })) { $idClaims += @{ name = 'auth_time'; essential = $false } }
        $claims['idToken'] = @($idClaims)
        Invoke-Graph 'PATCH' "/applications/$($app['id'])" @{
            web                    = $web
            requiredResourceAccess = @(@{ resourceAppId = $GraphAppId; resourceAccess = $SignInScopes })
            optionalClaims         = $claims
        } | Out-Null
    }
    $appObjectId = $app['id']
    $clientId = $app['appId']

    # Its service principal (the app's presence in this tenant), so users can sign in.
    $sp = Get-First ('/servicePrincipals?$filter=' + (Enc "appId eq '$clientId'") + '&$select=id')
    if ($null -eq $sp) {
        # A brand-new app takes a few seconds to reach every Microsoft server: retry for about 30 seconds.
        for ($try = 1; $null -eq $sp; $try++) {
            try {
                $sp = Invoke-Graph 'POST' '/servicePrincipals' @{ appId = $clientId; tags = @('WindowsAzureActiveDirectoryIntegratedApp') }
            } catch {
                if ($try -ge 6) { throw }
                Start-Sleep -Seconds (2 * $try)
            }
        }
    }

    # Organisation-wide consent for the sign-in permissions only (otherwise each user is asked, or blocked by policy).
    try {
        $graphSp = Get-First ('/servicePrincipals?$filter=' + (Enc "appId eq '$GraphAppId'") + '&$select=id')
        $grant = Get-First ('/oauth2PermissionGrants?$filter=' + (Enc "clientId eq '$($sp['id'])' and consentType eq 'AllPrincipals' and resourceId eq '$($graphSp['id'])'"))
        if ($null -eq $grant) {
            Invoke-Graph 'POST' '/oauth2PermissionGrants' @{ clientId = $sp['id']; consentType = 'AllPrincipals'; resourceId = $graphSp['id']; scope = 'openid profile email' } | Out-Null
        } elseif ($grant['scope'] -notmatch '\bemail\b' -or $grant['scope'] -notmatch '\bprofile\b' -or $grant['scope'] -notmatch '\bopenid\b') {
            Invoke-Graph 'PATCH' "/oauth2PermissionGrants/$($grant['id'])" @{ scope = 'openid profile email' } | Out-Null
        }
        Say 'Sign-in permissions granted for the organisation (openid, profile, email)'
    } catch {
        Write-Warning "Could not grant consent for the organisation ($($_.Exception.Message)). In the Entra admin center, open the app's API permissions and click ""Grant admin consent"", or users are asked to consent the first time."
    }

    # A new client secret.
    $until = (Get-Date).ToUniversalTime().AddMonths($SecretMonths)
    $pw = Invoke-Graph 'POST' "/applications/$appObjectId/addPassword" @{ passwordCredential = @{ displayName = "$SecretPrefix $((Get-Date).ToString('yyyy-MM-dd'))"; endDateTime = $until.ToString('o') } }
    $newKeyId = $pw['keyId']
    $secret = $pw['secretText']
    # Invariant culture: some regional settings would otherwise change the time separator.
    $expires = ([datetime]$pw['endDateTime']).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)

    # Hand it to Sentinel with the setup code. Microsoft may take a minute to accept a new secret; Sentinel only stores it.
    Say 'Sending the app details to Sentinel'
    $payload = @{ code = $code; tenant_id = $tenant; client_id = $clientId; client_secret = $secret; secret_expires = $expires; redirect_uri = $Redirect } | ConvertTo-Json
    $secret = $null
    try {
        $answer = Invoke-RestMethod -Method Post -Uri "$Server/sso-setup/v1/receive" -ContentType 'application/json' -Body $payload -UseBasicParsing
    } catch {
        $msg = $_.Exception.Message
        $details = $_.ErrorDetails  # Sentinel's JSON answer ({"ok":false,"message":...}), when there is one
        if ($null -ne $details -and $details.Message) {
            $msg = $details.Message
            try { $msg = ($details.Message | ConvertFrom-Json).message } catch { $msg = $details.Message }
        }
        Fail "Sentinel did not accept the app details: $msg"
    } finally {
        $payload = $null
        $code = $null
    }
    if (-not $answer.ok) { Fail "Sentinel did not accept the app details: $($answer.message)" }
    $saved = $newKeyId
    $newKeyId = $null  # Sentinel has it now: keep this secret even if the clean-up below fails

    # Renewal: remove the older secrets this script made (other secrets are left alone).
    $current = Invoke-Graph 'GET' "/applications/$($appObjectId)?`$select=passwordCredentials"
    foreach ($c in @($current['passwordCredentials'])) {
        if ($c['keyId'] -ne $saved -and [string]$c['displayName'] -like "$SecretPrefix*") {
            try {
                Invoke-Graph 'POST' "/applications/$appObjectId/removePassword" @{ keyId = $c['keyId'] } | Out-Null
                Say "Removed the older secret ""$($c['displayName'])"""
            } catch {
                Write-Warning "Could not remove the older secret ""$($c['displayName'])"": remove it in the Entra admin center."
            }
        }
    }

    Say "Done. $($answer.message)"
    Say "The secret expires on $($until.ToString('yyyy-MM-dd')); Sentinel reminds admins 30 days before. Run this again with a new setup code to renew it."
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    # A secret Sentinel never received is removed again, so none is left behind unused.
    if ($connected -and $newKeyId -and $appObjectId) {
        try { Invoke-Graph 'POST' "/applications/$appObjectId/removePassword" @{ keyId = $newKeyId } | Out-Null } catch { Write-Warning 'Remove the unused new client secret in the Entra admin center.' }
    }
    $global:LASTEXITCODE = 1
} finally {
    if ($connected) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
}

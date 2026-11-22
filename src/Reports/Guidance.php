<?php

declare(strict_types=1);

namespace Sentinel\Reports;

/**
 * Plain-English explanations for report readers: what a finding means for
 * the business, and how to fix it.
 *
 * The text is written here (trusted). The finding's own key and data are
 * untrusted scan data and are only used to pick a text, never inserted into
 * it except through __() placeholders, which the report templates escape.
 */
final class Guidance
{
    /** Database and data-store ports: "your data is directly reachable". */
    private const DATA_PORTS = [1433, 1521, 3306, 5432, 6379, 9200, 27017];
    /** Remote-control ports: "someone could take over a computer". */
    private const REMOTE_PORTS = [3389, 5900, 5985, 5986, 23];
    /** Windows file sharing and RPC. */
    private const WINDOWS_PORTS = [135, 139, 445];

    /**
     * Guidance for one finding.
     *
     * @param array<string,mixed> $f Finding row (finding_key, finding_type, severity, cve_id).
     * @param array<string,mixed> $vuln Extra vulnerability data (in_kev, kev_action) when it is a CVE.
     * @return array{meaning:string, fix:string}
     */
    public static function for(array $f, array $vuln = []): array
    {
        $key = (string) $f['finding_key'];
        return match ((string) $f['finding_type']) {
            'port' => self::port((int) substr($key, (int) strrpos($key, ':') + 1)),
            'tls' => self::tls(substr($key, (int) strrpos($key, ':') + 1)),
            'web' => self::web(substr($key, (int) strrpos($key, ':') + 1)),
            'vuln' => self::vuln($vuln),
            'email' => self::email(substr($key, (int) strrpos($key, ':') + 1)),
            'device', 'patch' => self::device(substr($key, (int) strrpos($key, ':') + 1)),
            default => ['meaning' => __('This item needs a review by your IT provider.'), 'fix' => __('Review the details and decide whether to fix or accept it.')],
        };
    }

    /** @return array{meaning:string, fix:string} */
    private static function port(int $port): array
    {
        if (in_array($port, self::REMOTE_PORTS, true)) {
            return [
                'meaning' => __('Anyone on the internet can try to log in and take control of this computer. This is one of the most common ways ransomware gets in.'),
                'fix' => __('Close the port on the firewall. Give remote access through a VPN or a remote-access gateway with multi-factor authentication instead.'),
            ];
        }
        if (in_array($port, self::DATA_PORTS, true)) {
            return [
                'meaning' => __('A database can be reached directly from the internet. If a password is weak or the software has a flaw, your data could be read or deleted.'),
                'fix' => __('Close the port on the firewall so only the systems that need the database can reach it (for example over a VPN or private network).'),
            ];
        }
        if (in_array($port, self::WINDOWS_PORTS, true)) {
            return [
                'meaning' => __('Windows file sharing or management services are open to the internet. Attackers and worms scan for these constantly.'),
                'fix' => __('Block these ports on the firewall. Share files through a secure service or over a VPN.'),
            ];
        }
        if ($port === 21) {
            return [
                'meaning' => __('Files and passwords sent to this server travel unencrypted and can be read by others on the way.'),
                'fix' => __('Switch to an encrypted method (SFTP or FTPS), then close port 21.'),
            ];
        }
        return [
            'meaning' => __('A service is reachable from the internet that usually should not be.'),
            'fix' => __('Check whether this service needs to be public. If not, close the port on the firewall.'),
        ];
    }

    /** @return array{meaning:string, fix:string} */
    private static function tls(string $code): array
    {
        return match ($code) {
            'cert_expired' => [
                'meaning' => __('Visitors get a security warning, and some systems refuse to connect at all.'),
                'fix' => __('Renew the certificate now and set up automatic renewal.'),
            ],
            'cert_expiring' => [
                'meaning' => __('The certificate runs out soon. After that, visitors get security warnings.'),
                'fix' => __('Renew the certificate before it expires, ideally with automatic renewal.'),
            ],
            'cert_self_signed', 'cert_untrusted' => [
                'meaning' => __('Browsers can\'t confirm who runs this site, so users see warnings and learn to click past them.'),
                'fix' => __('Install a certificate from a trusted certificate authority, including the full chain.'),
            ],
            'cert_name_mismatch' => [
                'meaning' => __('The certificate is for a different name, so visitors get a security warning.'),
                'fix' => __('Install a certificate that covers this exact host name.'),
            ],
            'tls_old_protocol' => [
                'meaning' => __('The server still allows old encryption versions with known weaknesses.'),
                'fix' => __('Turn off TLS 1.0 and 1.1 on the server, leaving TLS 1.2 and 1.3.'),
            ],
            'cert_weak_key', 'cert_weak_signature' => [
                'meaning' => __('The certificate uses weak cryptography that may be broken.'),
                'fix' => __('Replace it with a certificate using a 2048-bit (or larger) RSA or a modern EC key and a SHA-256 signature.'),
            ],
            default => [
                'meaning' => __('The certificate has a problem that may cause warnings or weaken encryption.'),
                'fix' => __('Review and replace the certificate.'),
            ],
        };
    }

    /** @return array{meaning:string, fix:string} */
    private static function web(string $category): array
    {
        return match ($category) {
            'login_over_http' => [
                'meaning' => __('Passwords typed on this page travel unencrypted and can be read on the way (public Wi-Fi, compromised networks).'),
                'fix' => __('Serve the site only over HTTPS and redirect every HTTP request to HTTPS.'),
            ],
            'no_https_redirect' => [
                'meaning' => __('Visitors who type the address without https:// get an unencrypted version of the site, which can be read or changed on the way.'),
                'fix' => __('Redirect all HTTP requests to the HTTPS address (a permanent 301 redirect).'),
            ],
            'missing_hsts' => [
                'meaning' => __('Browsers are not told to always use HTTPS, so a first visit or an old link can be downgraded to unencrypted HTTP.'),
                'fix' => __('Add the header Strict-Transport-Security: max-age=31536000 (one year) once HTTPS works everywhere on the site.'),
            ],
            'missing_csp' => [
                'meaning' => __('Without a Content-Security-Policy, an injected script (for example from a hacked plugin or a cross-site scripting bug) runs with no restriction.'),
                'fix' => __('Add a Content-Security-Policy header that allows scripts and styles only from the site and the services it really uses; start in report-only mode to test it.'),
            ],
            'insecure_cookies' => [
                'meaning' => __('Cookies without Secure can be sent over unencrypted connections, and session cookies without HttpOnly can be stolen by injected scripts.'),
                'fix' => __('Set the Secure flag on all cookies of HTTPS sites and HttpOnly on session and login cookies (usually a setting in the site or framework).'),
            ],
            'directory_listing' => [
                'meaning' => __('Anyone can browse the files in a folder of the website, including files that were never meant to be public.'),
                'fix' => __('Turn off directory listing in the web server configuration (for example "Options -Indexes" in Apache, "autoindex off" in Nginx).'),
            ],
            'exposed_git' => [
                'meaning' => __('The website\'s source code history can be downloaded, often including passwords, keys and the full code.'),
                'fix' => __('Block access to the .git folder in the web server (or remove it from the web root), then change any passwords or keys it contained.'),
            ],
            'exposed_env' => [
                'meaning' => __('The site\'s configuration file can be downloaded. These files usually hold database passwords and API keys.'),
                'fix' => __('Block access to .env files (move them out of the web root), then change every password and key in the file: assume they are known.'),
            ],
            'exposed_backup' => [
                'meaning' => __('A backup or database export can be downloaded by anyone, possibly including customer data and passwords.'),
                'fix' => __('Remove the backup files from the website and store backups outside the web root. Check whether personal data was exposed.'),
            ],
            'exposed_phpinfo' => [
                'meaning' => __('A diagnostic page shows the server\'s full PHP configuration, which helps attackers plan an attack.'),
                'fix' => __('Delete the phpinfo page from the server.'),
            ],
            'exposed_status' => [
                'meaning' => __('The web server\'s status page shows live requests and internal details to anyone.'),
                'fix' => __('Allow the server-status page only from the server itself or a management network.'),
            ],
            'exposed_dsstore' => [
                'meaning' => __('A file left by a Mac lists the names of files in that folder, which can reveal hidden or old files.'),
                'fix' => __('Delete .DS_Store files from the website and block them in the web server.'),
            ],
            'firewall_admin', 'device_admin' => [
                'meaning' => __('The login page that controls a network device is open to the whole internet. If it is broken into, the attacker controls your network.'),
                'fix' => __('Allow management only from inside the network or a VPN, and keep the device\'s firmware up to date.'),
            ],
            'vpn_portal' => [
                'meaning' => __('VPN portals are a favourite target. Unpatched ones are regularly used to break into companies.'),
                'fix' => __('Keep the VPN firmware patched and require multi-factor authentication for every user.'),
            ],
            'remote_desktop_web' => [
                'meaning' => __('Remote desktop through the browser is available to anyone who has a password.'),
                'fix' => __('Require multi-factor authentication and keep the software patched.'),
            ],
            default => [
                'meaning' => __('An administrative page is reachable from the internet.'),
                'fix' => __('Limit access to trusted networks.'),
            ],
        };
    }

    /** @return array{meaning:string, fix:string} */
    private static function email(string $code): array
    {
        return match ($code) {
            'spf_pass_all' => [
                'meaning' => __('The domain\'s SPF record tells receivers that ANY server may send email as this domain, which makes fake emails from it easy.'),
                'fix' => __('Replace "+all" with "-all" (or "~all" while testing) and list only the services that really send your email.'),
            ],
            'spf_missing', 'spf_weak', 'spf_multiple' => [
                'meaning' => __('Receivers can\'t reliably tell real email from this domain apart from fakes, so phishing that pretends to be you gets through more easily.'),
                'fix' => __('Publish one SPF record listing the services that send your email, ending in "-all" or "~all" (for example v=spf1 include:spf.protection.outlook.com -all).'),
            ],
            'dmarc_missing', 'dmarc_weak' => [
                'meaning' => __('Without an enforced DMARC policy, receivers deliver emails that fake your domain, and you get no reports about them.'),
                'fix' => __('Publish a DMARC record (start with p=none and reports, then move to p=quarantine and p=reject once your real email passes).'),
            ],
            default => [
                'meaning' => __('An email security setting for this domain should be reviewed.'),
                'fix' => __('Review the domain\'s SPF, DKIM and DMARC records.'),
            ],
        };
    }

    /** @return array{meaning:string, fix:string} */
    private static function device(string $code): array
    {
        return match ($code) {
            'os_unsupported' => [
                'meaning' => __('This computer runs a Windows version that no longer gets security fixes. New flaws found in it stay open for good.'),
                'fix' => __('Upgrade to a supported Windows version, or replace the computer. If it is enrolled in Extended Security Updates, record that and accept the risk until the end of ESU.'),
            ],
            'av_missing', 'av_off' => [
                'meaning' => __('The computer has no working antivirus or EDR, so malware and ransomware can run without being stopped or noticed.'),
                'fix' => __('Install or turn on the company\'s antivirus/EDR and find out why it was missing or switched off.'),
            ],
            'av_outdated' => [
                'meaning' => __('The antivirus can\'t recognise recent threats because its definitions are out of date.'),
                'fix' => __('Check that the antivirus can update (internet access, licence, service running) and force an update.'),
            ],
            'encryption_off' => [
                'meaning' => __('If this computer is lost or stolen, anyone can read the files on its disk.'),
                'fix' => __('Turn on disk encryption (BitLocker on Windows, FileVault on Mac) and store the recovery key safely.'),
            ],
            'patches_missing' => [
                'meaning' => __('Security updates have been available for more than 30 days but are not installed, so known flaws stay open on this computer.'),
                'fix' => __('Install the listed updates (approve them in the patch policy if needed) and restart the computer.'),
            ],
            'smb1' => [
                'meaning' => __('This device still speaks SMBv1, the file-sharing protocol that let worms like WannaCry spread through whole networks.'),
                'fix' => __('Turn off SMBv1 (Windows: "Turn Windows features on or off" or Set-SmbServerConfiguration -EnableSMB1Protocol $false; on a NAS or printer, in its settings). Replace devices that only speak SMBv1.'),
            ],
            'smb_signing' => [
                'meaning' => __('SMB connections to this device aren\'t signed, so an attacker on the network can relay or alter them (a common way to take over a domain).'),
                'fix' => __('Require SMB signing (Group Policy: "Microsoft network server: Digitally sign communications (always)"), starting with servers and domain controllers.'),
            ],
            'rdp_no_nla' => [
                'meaning' => __('Remote Desktop shows the login screen to anyone before they authenticate, which helps password guessing and exposes the server to pre-login flaws.'),
                'fix' => __('Turn on "Require Network Level Authentication" for Remote Desktop (System Properties > Remote, or Group Policy).'),
            ],
            'telnet', 'ftp' => [
                'meaning' => __('This service sends passwords and data unencrypted, so anyone on the network can read them.'),
                'fix' => __('Turn the service off and use SSH or SFTP instead. For network devices, switch management to SSH or HTTPS.'),
            ],
            'http_login' => [
                'meaning' => __('A login page is served without encryption, so the password can be read by anyone on the network.'),
                'fix' => __('Turn on HTTPS for the device\'s web interface and turn off plain HTTP (or redirect it to HTTPS).'),
            ],
            'snmp_private', 'snmp_public' => [
                'meaning' => __('SNMP accepts a well-known default community string, so anyone on the network can read (with "private" often also change) the device\'s settings.'),
                'fix' => __('Change the community strings to long random values, or better, switch to SNMPv3 with authentication; turn SNMP off if nothing uses it.'),
            ],
            'patches_failed' => [
                'meaning' => __('Updates tried to install but failed, so the computer may be missing security fixes without anyone noticing.'),
                'fix' => __('Check the error on the device (disk space, pending restart, broken update service), fix it and retry the updates.'),
            ],
            default => [
                'meaning' => __('A security setting on this computer should be reviewed.'),
                'fix' => __('Review the device in your RMM tool.'),
            ],
        };
    }

    /**
     * @param array<string,mixed> $vuln
     * @return array{meaning:string, fix:string}
     */
    private static function vuln(array $vuln): array
    {
        $kev = (int) ($vuln['in_kev'] ?? 0) === 1;
        $action = trim((string) ($vuln['kev_action'] ?? ''));
        return [
            'meaning' => $kev
                ? __('This software flaw is being used by attackers right now (it is on the US government\'s known-exploited list).')
                : __('The software version reported has a published security flaw that an attacker could use.'),
            'fix' => $action !== ''
                ? __('Update the software to a fixed version. Official guidance: {action}', ['action' => mb_strimwidth($action, 0, 300, '…')])
                : __('Update the software to a version that fixes this flaw. If the vendor\'s build carries a backported fix, record that and mark it as a false positive.'),
        ];
    }
}

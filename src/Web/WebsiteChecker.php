<?php

declare(strict_types=1);

namespace Sentinel\Web;

use Sentinel\Scanning\HttpProbe;

/**
 * Website checks for one web service: HTTPS and redirect, security headers,
 * cookie settings, CMS and JavaScript library versions, directory listing,
 * and a short fixed list of commonly exposed files.
 *
 * Gentle by design: it reuses the "/" response Sentinel already fetched and
 * adds at most EXPOSED_PATHS requests per service, each a plain GET for a
 * fixed path with a small body cap. Nothing is posted, guessed or brute-forced.
 *
 * Honest by design: an exposed file only counts when its CONTENT proves it
 * (a Git ref, an env-style KEY=value file, a zip/gzip/SQL dump signature,
 * the Apache status page, phpinfo output). A site that answers "200 OK" to
 * every path is not reported. The content of exposed files is never stored.
 *
 * Security assumptions: every response is untrusted. Only fixed patterns are
 * matched; stored strings are short and cleaned; the caller checks scope
 * right before calling, and HttpProbe pins every request to that IP.
 */
final class WebsiteChecker
{
    /** path => [code, kind] (kind decides the content check). */
    public const EXPOSED_PATHS = [
        '/.git/HEAD' => ['exposed_git', 'git'],
        '/.env' => ['exposed_env', 'env'],
        '/backup.zip' => ['exposed_backup', 'archive'],
        '/backup.tar.gz' => ['exposed_backup', 'archive'],
        '/backup.sql' => ['exposed_backup', 'sql'],
        '/database.sql' => ['exposed_backup', 'sql'],
        '/phpinfo.php' => ['exposed_phpinfo', 'phpinfo'],
        '/server-status' => ['exposed_status', 'status'],
        '/.DS_Store' => ['exposed_dsstore', 'dsstore'],
    ];

    /** CPE (2.2 URI form, as nmap reports and Cpe::parse() reads) for detected components; the version is appended. */
    public const CPES = [
        'WordPress' => 'cpe:/a:wordpress:wordpress',
        'Drupal' => 'cpe:/a:drupal:drupal',
        'Joomla' => 'cpe:/a:joomla:joomla!',
        'jQuery' => 'cpe:/a:jquery:jquery',
        'Bootstrap' => 'cpe:/a:getbootstrap:bootstrap',
        'AngularJS' => 'cpe:/a:angularjs:angular.js',
        'Lodash' => 'cpe:/a:lodash:lodash',
        'Moment.js' => 'cpe:/a:momentjs:moment',
        'Vue.js' => 'cpe:/a:vuejs:vue.js',
    ];

    /** Library patterns over script URLs: name => list of regexes capturing the version. */
    private const LIBRARIES = [
        'jQuery' => ['~jquery[-.](\d+\.\d+\.\d+)(?:\.slim)?(?:\.min)?\.js~i', '~/jquery/(\d+\.\d+\.\d+)/~i', '~jquery@(\d+\.\d+\.\d+)~i'],
        'Bootstrap' => ['~bootstrap(?:\.bundle)?[-.](\d+\.\d+\.\d+)(?:\.min)?\.js~i', '~/(?:twitter-)?bootstrap/(\d+\.\d+\.\d+)/~i', '~bootstrap@(\d+\.\d+\.\d+)~i'],
        'AngularJS' => ['~angular[-.](1\.\d+\.\d+)(?:\.min)?\.js~i', '~/angular\.js/(1\.\d+\.\d+)/~i', '~angular@(1\.\d+\.\d+)~i'],
        'Lodash' => ['~lodash[-.](\d+\.\d+\.\d+)(?:\.min)?\.js~i', '~/lodash(?:\.js)?/(\d+\.\d+\.\d+)/~i', '~lodash@(\d+\.\d+\.\d+)~i'],
        'Moment.js' => ['~moment[-.](\d+\.\d+\.\d+)(?:\.min)?\.js~i', '~/moment(?:\.js)?/(\d+\.\d+\.\d+)/~i', '~moment@(\d+\.\d+\.\d+)~i'],
        'Vue.js' => ['~/vue/(\d+\.\d+\.\d+)/~i', '~vue@(\d+\.\d+\.\d+)~i'],
    ];

    /** Half a year: the usual minimum for HSTS. */
    private const HSTS_MIN = 15552000;

    /** @param HttpProbe $probe For the exposed-file requests (pinned, scope already checked by the caller). */
    public function __construct(private readonly HttpProbe $probe)
    {
    }

    /**
     * Analyse the "/" response.
     *
     * @param array{status:int, headers:array<string,string>, header_list:list<array{0:string,1:string}>, body:string} $r
     * @return array<string,mixed> The stored result (see class notes).
     */
    public static function analyse(array $r, string $scheme): array
    {
        $h = $r['headers'];
        $status = $r['status'];
        $body = $r['body'];
        $out = ['scheme' => $scheme, 'status' => $status, 'issues' => [], 'info' => [], 'components' => []];
        $isHtml = str_contains(strtolower($h['content-type'] ?? 'text/html'), 'html');
        $loc = (string) ($h['location'] ?? '');
        $redirectsToHttps = $status >= 300 && $status < 400 && str_starts_with(strtolower($loc), 'https://');

        if ($scheme === 'http') {
            $hasPassword = preg_match('/<input[^>]+type\s*=\s*["\']?password/i', $body) === 1;
            if ($status >= 200 && $status < 300 && $hasPassword) {
                $out['issues'][] = 'login_over_http';
            } elseif ($status >= 200 && $status < 300) {
                $out['issues'][] = 'no_https_redirect';
            }
        } elseif ($status > 0 && $status < 400) {
            $hsts = (string) ($h['strict-transport-security'] ?? '');
            if ($hsts === '') {
                $out['issues'][] = 'missing_hsts';
            } elseif (preg_match('/max-age\s*=\s*"?(\d+)/i', $hsts, $m) && (int) $m[1] < self::HSTS_MIN) {
                $out['info'][] = 'short_hsts';
            }
        }
        // Header advice only for HTTPS pages: a plain-HTTP page is already flagged for not using HTTPS.
        if ($scheme === 'https' && $status >= 200 && $status < 300 && $isHtml) {
            $csp = (string) ($h['content-security-policy'] ?? '');
            if ($csp === '') {
                $out['issues'][] = 'missing_csp';
            }
            if (!isset($h['x-frame-options']) && !preg_match('/frame-ancestors/i', $csp)) {
                $out['info'][] = 'missing_frame';
            }
            if (strtolower($h['x-content-type-options'] ?? '') !== 'nosniff') {
                $out['info'][] = 'missing_nosniff';
            }
            if (!isset($h['referrer-policy'])) {
                $out['info'][] = 'missing_referrer';
            }
        }
        if ($status >= 200 && $status < 300 && $isHtml && preg_match('~<title>\s*Index of /~i', $body)) {
            $out['issues'][] = 'directory_listing';
        }
        // Cookies: Secure on HTTPS, HttpOnly on session-like cookies; SameSite is advice only.
        $insecure = [];
        foreach ($r['header_list'] as [$name, $value]) {
            if ($name !== 'set-cookie') {
                continue;
            }
            $cookie = strtolower($value);
            $cname = trim((string) strtok($value, '='));
            $session = preg_match('/sess|sid|auth|token|login|jwt/i', $cname) === 1;
            if (($scheme === 'https' && !preg_match('/;\s*secure\b/', $cookie)) || ($session && !preg_match('/;\s*httponly\b/', $cookie))) {
                $insecure[] = mb_substr(preg_replace('/[^A-Za-z0-9_.-]/', '', $cname) ?: '?', 0, 40);
            }
            if (!preg_match('/;\s*samesite=/', $cookie)) {
                $out['info'][] = 'missing_samesite';
            }
        }
        if ($insecure !== []) {
            $out['issues'][] = 'insecure_cookies';
            $out['cookies'] = array_values(array_unique(array_slice($insecure, 0, 10)));
        }
        $out['info'] = array_values(array_unique($out['info']));
        if ($status >= 200 && $status < 300 && $isHtml) {
            $out['components'] = self::components($body, $h);
        }
        return $out;
    }

    /**
     * Detect a CMS and JavaScript libraries with versions.
     *
     * @param array<string,string> $headers
     * @return list<array{name:string, version:string, kind:string}>
     */
    public static function components(string $body, array $headers): array
    {
        $found = [];
        $html = substr($body, 0, 262144);
        $generator = '';
        if (preg_match('/<meta[^>]+name\s*=\s*["\']generator["\'][^>]*content\s*=\s*["\']([^"\']{1,120})/i', $html, $m)
            || preg_match('/<meta[^>]+content\s*=\s*["\']([^"\']{1,120})["\'][^>]*name\s*=\s*["\']generator/i', $html, $m)) {
            $generator = $m[1];
        }
        $xgen = (string) ($headers['x-generator'] ?? '');
        if (preg_match('/^WordPress\s+(\d+\.\d+(?:\.\d+)?)/i', $generator, $m)) {
            $found['WordPress'] = ['name' => 'WordPress', 'version' => $m[1], 'kind' => 'cms'];
        } elseif (preg_match('~/wp-(content|includes)/~i', $html)) {
            $found['WordPress'] = ['name' => 'WordPress', 'version' => '', 'kind' => 'cms'];
        }
        if (preg_match('/^Drupal\b/i', $generator) || preg_match('/^Drupal\b/i', $xgen)) {
            $found['Drupal'] = ['name' => 'Drupal', 'version' => '', 'kind' => 'cms']; // only the major version is ever shown: not enough to match
        }
        if (preg_match('/^Joomla!/i', $generator)) {
            $found['Joomla'] = ['name' => 'Joomla', 'version' => '', 'kind' => 'cms'];
        }
        $srcs = [];
        if (preg_match_all('/<script[^>]+src\s*=\s*["\']([^"\']{1,500})["\']/i', $html, $mm)) {
            $srcs = array_slice($mm[1], 0, 100);
        }
        foreach (self::LIBRARIES as $name => $patterns) {
            foreach ($srcs as $src) {
                foreach ($patterns as $re) {
                    if (preg_match($re, $src, $m)) {
                        $found[$name] ??= ['name' => $name, 'version' => $m[1], 'kind' => 'library'];
                        continue 3;
                    }
                }
            }
        }
        return array_values($found);
    }

    /**
     * Request the fixed list of paths and report the ones whose content proves exposure.
     *
     * @param callable $shouldStop fn(): bool, checked before each request (kill switch, window, scope).
     * @return array{codes:list<string>, complete:bool} Codes found (e.g. exposed_git); complete is false if
     *         the run stopped early or a request failed, so earlier results for unchecked files must be kept.
     */
    public function exposedFiles(string $ip, int $port, string $scheme, ?string $host, callable $shouldStop): array
    {
        $found = [];
        $complete = true;
        foreach (self::EXPOSED_PATHS as $path => [$code, $kind]) {
            if (isset($found[$code])) {
                continue;
            }
            if ($shouldStop()) {
                $complete = false;
                break;
            }
            $r = $this->probe->request($ip, $port, $scheme, $host, $path, 4096);
            if ($r['status'] === 0) {
                $complete = false; // no answer: unknown, not "fixed"
                continue;
            }
            if ($r['status'] !== 200 && $r['status'] !== 206) {
                continue;
            }
            if (self::proves($kind, $r['body'], strtolower($r['headers']['content-type'] ?? ''))) {
                $found[$code] = true;
            }
        }
        return ['codes' => array_keys($found), 'complete' => $complete];
    }

    /** True if the first bytes of a response prove the file is what its path says. */
    public static function proves(string $kind, string $body, string $contentType): bool
    {
        $start = ltrim(substr($body, 0, 4096));
        $looksHtml = str_contains($contentType, 'html') || preg_match('/^\s*<(!doctype|html|head|body)/i', $start) === 1;
        return match ($kind) {
            'git' => preg_match('~^ref: refs/heads/[\w./-]+\s*$~', trim($start)) === 1 || preg_match('/^[0-9a-f]{40}\s*$/', trim($start)) === 1,
            'env' => !$looksHtml && preg_match_all('/^\s*[A-Z][A-Z0-9_]{2,}\s*=/m', $start) >= 2,
            'archive' => str_starts_with($body, "PK\x03\x04") || str_starts_with($body, "\x1f\x8b"),
            'sql' => !$looksHtml && preg_match('/^(--\s*(MySQL|MariaDB) dump|CREATE TABLE|INSERT INTO|DROP TABLE|-- PostgreSQL database dump)/im', $start) === 1,
            'phpinfo' => str_contains($body, 'phpinfo()') && preg_match('/PHP Version\s*</', $body) === 1,
            'status' => preg_match('/<title>Apache Status<\/title>|Apache Server Status for/i', $body) === 1,
            'dsstore' => str_starts_with($body, "\x00\x00\x00\x01Bud1"),
            default => false,
        };
    }
}

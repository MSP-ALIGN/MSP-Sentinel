<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

/**
 * Fetches "/" from one web port (a single GET, no redirects followed) and
 * classifies the page using generic signatures: VPN portals, firewall or
 * device admin pages, remote desktop web access, other login pages.
 *
 * No logins, no path guessing, no form submissions.
 *
 * Security assumptions:
 * - The caller has checked the IP against the scope right before calling.
 *   curl is pinned to that IP (CURLOPT_RESOLVE / CONNECT_TO), so the
 *   hostname used in the Host header can never send the request elsewhere.
 * - The response is UNTRUSTED: the body is capped at 256 KB and only read
 *   for its title and signatures. Stored values are cleaned and length-limited.
 * - TLS certificates aren't verified here (TlsChecker judges them).
 */
final class HttpProbe
{
    private const MAX_BODY = 262144;

    /**
     * Generic signatures, checked in order. They match on wording and page
     * structure only, never on vendor names. "strict" signatures use common
     * words (router, switch, firewall...), so they only count in the page's
     * title, headings, form labels or authentication realm, never in body text.
     * A webmail page with a "Switch language" link isn't a device admin page.
     */
    public const SIGNATURES = [
        ['category' => 'firewall_admin', 'label' => 'Firewall administration page', 'strict' => true,
         'pattern' => '/\b(firewall|security gateway|utm)\b.{0,80}\b(admin|administration|login|log in|sign in|management)\b|\b(admin|administration|management)\b.{0,80}\bfirewall\b/is'],
        ['category' => 'vpn_portal', 'label' => 'VPN login portal',
         'pattern' => '/\b(ssl[\s-]?vpn|vpn\s+(portal|login|gateway|client)|remote\s+access\s+(portal|login|vpn))\b/i'],
        ['category' => 'remote_desktop_web', 'label' => 'Remote desktop web access',
         'pattern' => '/\b(rd\s?web\s+access|remote\s+desktop\s+(web|gateway)|\/rdweb\/)/i'],
        ['category' => 'device_admin', 'label' => 'Device or server management page', 'strict' => true,
         'pattern' => '/\b(router|switch|nas|network\s+storage|printer|ups|ipmi|baseboard\s+management|lights[\s-]out|web\s?admin|admin(istration)?\s+(console|panel|interface)|management\s+(console|interface|portal)|device\s+management)\b/i'],
    ];

    /** @param int $timeout Seconds for the whole request. */
    public function __construct(private readonly Connector $connector, private readonly int $timeout = 10)
    {
    }

    /**
     * Fetch and classify.
     *
     * @param string      $ip         Target address (in scope).
     * @param string      $scheme     'http' or 'https'.
     * @param string|null $hostHeader In-scope hostname for this address, or null to use the IP.
     * @return array<string,mixed> Columns for web_pages plus 'ok'.
     */
    public function fetch(string $ip, int $port, string $scheme, ?string $hostHeader): array
    {
        $host = $hostHeader ?? (str_contains($ip, ':') ? '[' . $ip . ']' : $ip);
        $url = $scheme . '://' . $host . ':' . $port . '/';
        try {
            [$realHost, $realPort] = $this->connector->endpoint($ip, $port);
        } catch (\RuntimeException $ex) {
            return ['ok' => false, 'scheme' => $scheme, 'host_header' => (string) $hostHeader, 'last_error' => self::clean($ex->getMessage(), 300)];
        }
        $body = '';
        $headers = [];
        $ch = curl_init($url);
        $opts = [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => min(5, $this->timeout),
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_PROXY => '', // scans go straight to the target, never through a proxy
            CURLOPT_NOPROXY => '*',
            CURLOPT_USERAGENT => 'MSP-Sentinel exposure check',
            CURLOPT_HTTPHEADER => ['Accept: text/html,*/*;q=0.5'],
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body): int {
                $room = self::MAX_BODY - strlen($body);
                if ($room <= 0) {
                    return 0;
                }
                $body .= substr($chunk, 0, $room);
                return strlen($chunk);
            },
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$headers): int {
                if (count($headers) < 100 && str_contains($line, ':')) {
                    [$name, $value] = explode(':', $line, 2);
                    $headers[strtolower(trim($name))] = trim($value);
                }
                return strlen($line);
            },
        ];
        // Pin the connection to the scanned IP (or the test redirect), whatever the Host header says.
        if ($realHost !== $ip || $realPort !== $port) {
            $opts[CURLOPT_CONNECT_TO] = [$host . ':' . $port . ':' . $realHost . ':' . $realPort];
        } elseif ($hostHeader !== null) {
            $opts[CURLOPT_RESOLVE] = [$hostHeader . ':' . $port . ':' . (str_contains($ip, ':') ? '[' . $ip . ']' : $ip)];
        }
        curl_setopt_array($ch, $opts);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        if ($status === 0) {
            return ['ok' => false, 'scheme' => $scheme, 'host_header' => (string) $hostHeader, 'last_error' => self::clean(__('No HTTP response: {e}', ['e' => $error]), 300)];
        }
        $title = '';
        if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $body, $m)) {
            $title = self::clean(html_entity_decode(strip_tags($m[1]), ENT_QUOTES | ENT_HTML5, 'UTF-8'), 300);
        }
        [$category, $label] = self::classify($title, $body, $headers);
        return [
            'ok' => true,
            'scheme' => $scheme,
            'host_header' => (string) $hostHeader,
            'status_code' => $status,
            'title' => $title,
            'server_header' => self::clean($headers['server'] ?? '', 200),
            'redirect_to' => self::clean($headers['location'] ?? '', 500),
            'category' => $category,
            'matched' => $label,
            'last_error' => $ok === false && $status === 0 ? self::clean($error, 300) : '',
        ];
    }

    /**
     * Match title, visible text and headers against the signatures. A page
     * with a password field that matches nothing else is a generic login page.
     *
     * @param array<string,string> $headers Lower-cased names.
     * @return array{0:?string,1:string} [category or null, label]
     */
    public static function classify(string $title, string $body, array $headers): array
    {
        $hasLogin = preg_match('/<input[^>]+type\s*=\s*["\']?password/i', $body) === 1 || isset($headers['www-authenticate']);
        $clean = self::stripScripts($body);
        $realm = $headers['www-authenticate'] ?? '';
        $text = $title . "\n" . mb_substr(strip_tags($clean), 0, 20000) . "\n" . $realm;
        // Prominent text only: title, headings, labels and the auth realm.
        $prominent = $title . "\n" . $realm;
        if (preg_match_all('/<(h1|h2|label|legend)\b[^>]*>(.{0,300}?)<\/\1>/is', mb_substr($clean, 0, 65536), $m)) {
            $prominent .= "\n" . strip_tags(implode("\n", $m[2]));
        }
        foreach (self::SIGNATURES as $sig) {
            $haystack = !empty($sig['strict']) ? $prominent : $text;
            if (preg_match($sig['pattern'], $haystack)) {
                return [$sig['category'], $sig['label']];
            }
        }
        if ($hasLogin) {
            return ['login_page', 'Login page'];
        }
        return [null, ''];
    }

    /**
     * Remove <script> and <style> blocks in one linear pass (no backtracking
     * regex, so unclosed tags in a hostile page can't cost quadratic time).
     */
    private static function stripScripts(string $html): string
    {
        $out = '';
        $pos = 0;
        $lower = strtolower($html);
        while (true) {
            $s = strpos($lower, '<script', $pos);
            $t = strpos($lower, '<style', $pos);
            $start = $s === false ? $t : ($t === false ? $s : min($s, $t));
            if ($start === false) {
                return $out . substr($html, $pos);
            }
            $close = $start === $s ? '</script' : '</style';
            $out .= substr($html, $pos, $start - $pos) . ' ';
            $end = strpos($lower, $close, $start);
            if ($end === false) {
                return $out; // unclosed: drop the rest
            }
            $gt = strpos($lower, '>', $end);
            $pos = $gt === false ? strlen($html) : $gt + 1;
        }
    }

    /** Remove control characters and invalid UTF-8, then cut to $max characters. */
    private static function clean(string $value, int $max): string
    {
        $value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        return mb_substr(trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $value)), 0, $max);
    }
}

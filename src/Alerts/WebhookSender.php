<?php

declare(strict_types=1);

namespace Sentinel\Alerts;

use Sentinel\Scope\ScopeParser;

/**
 * Posts alert summaries to a webhook (Microsoft Teams Workflows, Slack, or generic JSON).
 *
 * Security assumptions:
 * - The URL is admin-entered and holds a secret token: it is stored
 *   encrypted, never logged, and error messages never include it.
 * - Against SSRF (the server being used to reach internal systems): only
 *   https is allowed, and the host must resolve to PUBLIC addresses only.
 *   The request is pinned to the checked address (CURLOPT_RESOLVE), so a DNS
 *   change between check and use (rebinding) can't redirect it. Redirects
 *   are not followed. Plain http to 127.0.0.1 is allowed only in the test suite
 *   (App::webhookTestMode(): a config flag AND an environment variable only
 *   the test harness sets). No proxy is ever used, and the address actually
 *   connected to is checked against the pinned one.
 * - Payloads contain only alert summaries (client name, finding titles, grades, links).
 */
final class WebhookSender
{
    public const FORMATS = ['teams', 'slack', 'json'];

    /** @param bool $testMode Allow http://127.0.0.1 (test suite only). */
    public function __construct(private readonly bool $testMode = false, private readonly int $timeout = 10)
    {
    }

    /**
     * Check a webhook URL and work out where to connect.
     *
     * @return array{host:string, port:int, ip:string}|string Connection details, or an error message.
     */
    public function check(string $url): array|string
    {
        $parts = parse_url($url);
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));
        if ($host === '' || isset($parts['user']) || isset($parts['pass']) || strlen($url) > 2000) {
            return __('Enter a full webhook address.');
        }
        if ($this->testMode && $scheme === 'http' && $host === '127.0.0.1') {
            return ['host' => $host, 'port' => (int) ($parts['port'] ?? 80), 'ip' => '127.0.0.1'];
        }
        if ($scheme !== 'https') {
            return __('The webhook address must start with https://.');
        }
        $ips = filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) !== false ? [trim($host, '[]')] : (gethostbynamel($host) ?: []);
        if ($ips === []) {
            return __('The webhook host name could not be resolved.');
        }
        $parser = new ScopeParser(false);
        foreach ($ips as $ip) {
            if (is_string($parser->parse($ip))) {
                return __('The webhook host points to a private or reserved address, which is not allowed.');
            }
        }
        return ['host' => $host, 'port' => (int) ($parts['port'] ?? 443), 'ip' => $ips[0]];
    }

    /**
     * Send a payload.
     *
     * @param array<string,mixed> $payload Already formatted (see format()).
     * @throws \RuntimeException with a safe message (never the URL).
     */
    public function send(string $url, array $payload): void
    {
        $this->sendRaw($url, (string) json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE));
    }

    /**
     * Send an already-encoded JSON body with extra headers (signed events).
     *
     * @param list<string> $headers Extra "Name: value" headers (built by Sentinel, never from input).
     * @throws \RuntimeException with a safe message (never the URL).
     */
    public function sendRaw(string $url, string $body, array $headers = []): void
    {
        foreach ($headers as $h) {
            if (preg_match('/[\r\n]/', $h)) {
                throw new \RuntimeException('Refusing a header with a line break.');
            }
        }
        $target = $this->check($url);
        if (is_string($target)) {
            throw new \RuntimeException($target);
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => array_merge(['Content-Type: application/json'], $headers),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | ($this->testMode ? CURLPROTO_HTTP : 0),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_RESOLVE => [$target['host'] . ':' . $target['port'] . ':' . $target['ip']],
            // Never use a proxy from the environment: a proxy would resolve the host itself and defeat the pinning.
            CURLOPT_PROXY => '',
            CURLOPT_NOPROXY => '*',
            CURLOPT_USERAGENT => 'MSP-Sentinel alerts',
            CURLOPT_MAXFILESIZE => 1_000_000,
        ]);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $connected = (string) curl_getinfo($ch, CURLINFO_PRIMARY_IP);
        $error = curl_error($ch);
        curl_close($ch);
        if ($ok === false) {
            throw new \RuntimeException('Webhook could not be reached: ' . mb_substr((string) preg_replace('#https?://\S+#', '[url]', $error), 0, 150));
        }
        if ($connected !== $target['ip']) {
            throw new \RuntimeException('Webhook connection went to an unexpected address; not trusted.');
        }
        if ($status < 200 || $status >= 300) {
            throw new \RuntimeException('Webhook answered HTTP ' . $status . '.');
        }
    }

    /**
     * Build the payload for a format.
     *
     * @param array{title:string, text:string, severity:string, client:string, items:list<string>, link:string} $alert
     * @return array<string,mixed>
     */
    public static function format(string $format, array $alert): array
    {
        $lines = array_slice($alert['items'], 0, 20);
        return match ($format) {
            'teams' => [
                'type' => 'message',
                'attachments' => [[
                    'contentType' => 'application/vnd.microsoft.card.adaptive',
                    'content' => [
                        '$schema' => 'http://adaptivecards.io/schemas/adaptive-card.json',
                        'type' => 'AdaptiveCard',
                        'version' => '1.4',
                        'body' => array_merge(
                            [['type' => 'TextBlock', 'size' => 'Medium', 'weight' => 'Bolder', 'wrap' => true, 'text' => self::teamsEscape($alert['title']),
                              'color' => $alert['severity'] === 'fail' ? 'Attention' : ($alert['severity'] === 'warn' ? 'Warning' : 'Default')],
                             ['type' => 'TextBlock', 'wrap' => true, 'text' => self::teamsEscape($alert['text'])]],
                            array_map(static fn (string $l): array => ['type' => 'TextBlock', 'wrap' => true, 'spacing' => 'None', 'text' => '- ' . self::teamsEscape($l)], $lines)
                        ),
                        'actions' => $alert['link'] !== '' ? [['type' => 'Action.OpenUrl', 'title' => 'Open in Sentinel', 'url' => $alert['link']]] : [],
                    ],
                ]],
            ],
            'slack' => [
                'text' => $alert['title'],
                'blocks' => array_values(array_filter([
                    ['type' => 'section', 'text' => ['type' => 'mrkdwn', 'text' => '*' . self::slackEscape($alert['title']) . "*\n" . self::slackEscape($alert['text'])]],
                    $lines !== [] ? ['type' => 'section', 'text' => ['type' => 'mrkdwn', 'text' => implode("\n", array_map(static fn (string $l): string => '• ' . self::slackEscape($l), $lines))]] : null,
                    $alert['link'] !== '' ? ['type' => 'context', 'elements' => [['type' => 'mrkdwn', 'text' => '<' . $alert['link'] . '|Open in Sentinel>']]] : null,
                ])),
            ],
            default => [
                'source' => 'msp-sentinel',
                'severity' => $alert['severity'],
                'client' => $alert['client'],
                'title' => $alert['title'],
                'text' => $alert['text'],
                'items' => $lines,
                'link' => $alert['link'],
                'sent_at' => gmdate('c'),
            ],
        };
    }

    /**
     * Text for a Teams adaptive card TextBlock, which renders a subset of Markdown: the Markdown characters are
     * backslash-escaped so a device name or title (untrusted, from scans or integrations) shows literally and can't
     * add links or formatting (1.34 audit). Only the characters that make links, emphasis or code are escaped, so
     * addresses and versions (192.168.1.10, 2.4-1) read normally.
     */
    private static function teamsEscape(string $text): string
    {
        return (string) preg_replace('/([\\\\`*_\[\]()~])/', '\\\\$1', $text);
    }

    /** Escape Slack mrkdwn control characters in untrusted text. */
    private static function slackEscape(string $text): string
    {
        return str_replace(['&', '<', '>'], ['&amp;', '&lt;', '&gt;'], $text);
    }
}

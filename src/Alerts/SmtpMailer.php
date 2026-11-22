<?php

declare(strict_types=1);

namespace Sentinel\Alerts;

/**
 * A small SMTP client (no Composer): implicit TLS (port 465), STARTTLS
 * (port 587) or plain (only to a local relay on loopback), AUTH PLAIN or
 * LOGIN, one message to one or more recipients, UTF-8 plain text.
 *
 * Security assumptions:
 * - Server certificates are verified (system trust store, plus an extra CA
 *   file if configured). Credentials are never sent unencrypted: plain
 *   mode is refused unless the server is a loopback address.
 * - Addresses must pass FILTER_VALIDATE_EMAIL and may not contain CR/LF.
 *   Subjects are encoded (RFC 2047) and bodies dot-stuffed, so message
 *   content can't inject headers or SMTP commands.
 * - Server replies are only checked for their status code. Error messages
 *   never contain the password.
 */
final class SmtpMailer
{
    /**
     * @param string      $security 'tls' (implicit), 'starttls' or 'none' (loopback relays only).
     * @param string|null $caFile   CA bundle for verification (null = system default).
     */
    public function __construct(
        private readonly string $host,
        private readonly int $port,
        private readonly string $security,
        private readonly string $username,
        private readonly string $password,
        private readonly string $from,
        private readonly ?string $caFile = null,
        private readonly int $timeout = 20,
    ) {
    }

    /**
     * Send one message.
     *
     * @param list<string> $to Recipient addresses (validated here again).
     * @param list<array{name:string, type:string, content:string}> $attachments Files to attach (names are sanitised).
     * @throws \RuntimeException with a safe message on any failure.
     */
    public function send(array $to, string $subject, string $body, array $attachments = []): void
    {
        $to = array_values(array_filter($to, [self::class, 'validAddress']));
        if ($to === [] || !self::validAddress($this->from)) {
            throw new \RuntimeException('No valid sender or recipient address.');
        }
        if ($this->security === 'none' && !in_array($this->host, ['127.0.0.1', '::1', 'localhost'], true)) {
            throw new \RuntimeException('Unencrypted SMTP is only allowed to a relay on this server (127.0.0.1).');
        }
        $ctx = stream_context_create(['ssl' => array_filter([
            'verify_peer' => true, 'verify_peer_name' => true, 'peer_name' => $this->host, 'cafile' => $this->caFile,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
        ], static fn ($v) => $v !== null)]);
        $scheme = $this->security === 'tls' ? 'ssl' : 'tcp';
        $sock = @stream_socket_client($scheme . '://' . (str_contains($this->host, ':') ? '[' . $this->host . ']' : $this->host) . ':' . $this->port,
            $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $ctx);
        if ($sock === false) {
            throw new \RuntimeException('Could not connect to the mail server: ' . mb_substr($errstr, 0, 150));
        }
        stream_set_timeout($sock, $this->timeout);
        try {
            $this->expect($sock, 220);
            $ehloHost = 'msp-sentinel.local';
            $caps = $this->command($sock, 'EHLO ' . $ehloHost, 250);
            if ($this->security === 'starttls') {
                if (!str_contains(strtoupper($caps), 'STARTTLS')) {
                    throw new \RuntimeException('The mail server does not offer STARTTLS.');
                }
                $this->command($sock, 'STARTTLS', 220);
                if (@stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT) !== true) {
                    throw new \RuntimeException('TLS negotiation with the mail server failed (certificate not trusted or name mismatch).');
                }
                $caps = $this->command($sock, 'EHLO ' . $ehloHost, 250);
            }
            if ($this->username !== '') {
                if (preg_match('/AUTH[ =][^\r\n]*PLAIN/i', $caps)) {
                    $this->command($sock, 'AUTH PLAIN ' . base64_encode("\0" . $this->username . "\0" . $this->password), 235, true);
                } else {
                    $this->command($sock, 'AUTH LOGIN', 334);
                    $this->command($sock, base64_encode($this->username), 334, true);
                    $this->command($sock, base64_encode($this->password), 235, true);
                }
            }
            $this->command($sock, 'MAIL FROM:<' . $this->from . '>', 250);
            foreach ($to as $rcpt) {
                $this->command($sock, 'RCPT TO:<' . $rcpt . '>', [250, 251]);
            }
            $this->command($sock, 'DATA', 354);
            $this->write($sock, self::buildMessage($this->from, $to, $subject, $body, $attachments) . "\r\n.");
            $this->expect($sock, 250);
            // The message is accepted. A bad answer to QUIT must not make it look failed (and be sent again).
            try {
                $this->command($sock, 'QUIT', 221);
            } catch (\RuntimeException) {
            }
        } finally {
            fclose($sock);
        }
    }

    /**
     * The message headers and body, dot-stuffed for DATA (public for tests).
     *
     * @param list<string> $to
     * @param list<array{name:string, type:string, content:string}> $attachments
     */
    public static function buildMessage(string $from, array $to, string $subject, string $body, array $attachments = []): string
    {
        $subject = trim((string) preg_replace('/[\r\n\t]+/', ' ', $subject));
        $headers = [
            'From: MSP Sentinel <' . $from . '>',
            'To: ' . implode(', ', $to),
            // RFC 2047: encoded words of at most 75 characters, folded onto continuation lines.
            'Subject: ' . implode("\r\n ", array_map(static fn (string $part): string => '=?UTF-8?B?' . base64_encode($part) . '?=',
                mb_str_split(mb_substr($subject, 0, 200) === '' ? ' ' : mb_substr($subject, 0, 200), 30))),
            'Date: ' . gmdate('D, d M Y H:i:s') . ' +0000',
            'Message-ID: <' . bin2hex(random_bytes(12)) . '@msp-sentinel>',
            'MIME-Version: 1.0',
            'Auto-Submitted: auto-generated',
        ];
        $b64 = static fn (string $data): string => rtrim(chunk_split(base64_encode($data), 76, "\r\n"));
        $text = $b64(str_replace(["\r\n", "\r"], "\n", $body));
        if ($attachments === []) {
            $headers[] = 'Content-Type: text/plain; charset=UTF-8';
            $headers[] = 'Content-Transfer-Encoding: base64';
            $content = $text;
        } else {
            // multipart/mixed: the text, then each file. Everything is base64, so no part can break the structure.
            $boundary = '=_sentinel_' . bin2hex(random_bytes(12));
            $headers[] = 'Content-Type: multipart/mixed; boundary="' . $boundary . '"';
            $parts = ["--{$boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" . $text];
            foreach ($attachments as $a) {
                $name = substr((string) preg_replace('/[^A-Za-z0-9._-]+/', '-', $a['name']), 0, 100) ?: 'attachment';
                $type = preg_match('#^[a-z]+/[a-z0-9.+-]+$#', $a['type']) ? $a['type'] : 'application/octet-stream';
                $parts[] = "--{$boundary}\r\nContent-Type: {$type}; name=\"{$name}\"\r\nContent-Disposition: attachment; filename=\"{$name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" . $b64($a['content']);
            }
            $content = implode("\r\n", $parts) . "\r\n--{$boundary}--";
        }
        // Base64 lines never start with ".", but dot-stuff anyway in case the encoding ever changes.
        $lines = preg_replace('/^\./m', '..', $content);
        return implode("\r\n", $headers) . "\r\n\r\n" . $lines;
    }

    /** True for a single plain address with no header-breaking characters. */
    public static function validAddress(string $address): bool
    {
        return !preg_match('/[\r\n<>,;"]/', $address) && filter_var($address, FILTER_VALIDATE_EMAIL) !== false && strlen($address) <= 254;
    }

    /**
     * Send a command and expect a status code. Returns the reply text.
     *
     * @param int|list<int> $code
     * @param bool $secret Don't echo the command in errors (credentials).
     */
    private function command($sock, string $line, int|array $code, bool $secret = false): string
    {
        if (preg_match('/[\r\n]/', $line)) {
            throw new \RuntimeException('Refusing to send an SMTP command with a line break.');
        }
        $this->write($sock, $line);
        try {
            return $this->expect($sock, $code);
        } catch (\RuntimeException $ex) {
            throw new \RuntimeException(($secret ? 'Authentication' : strtok($line, ' ')) . ' failed: ' . $ex->getMessage());
        }
    }

    /** Write one line (CRLF terminated). */
    private function write($sock, string $data): void
    {
        if (@fwrite($sock, $data . "\r\n") === false) {
            throw new \RuntimeException('Lost the connection to the mail server.');
        }
    }

    /**
     * Read a (possibly multi-line) reply and check its code.
     *
     * @param int|list<int> $code
     */
    private function expect($sock, int|array $code): string
    {
        $reply = '';
        while (($line = fgets($sock, 1024)) !== false) {
            $reply .= $line;
            if (strlen($reply) > 16384) {
                break;
            }
            if (strlen($line) < 4 || $line[3] !== '-') {
                break;
            }
        }
        $got = (int) substr($reply, 0, 3);
        if (!in_array($got, (array) $code, true)) {
            throw new \RuntimeException('the mail server answered ' . ($got ?: 'nothing') . ' ' . mb_substr(trim(substr(strtok($reply, "\n"), 4)), 0, 120));
        }
        return $reply;
    }
}

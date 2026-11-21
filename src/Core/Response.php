<?php

declare(strict_types=1);

namespace Sentinel\Core;

/**
 * An HTTP response built by a controller and sent by the kernel.
 *
 * Security assumptions:
 * - redirect() only accepts app-relative paths, so user input can't turn
 *   it into an open redirect.
 * - Header values are checked for CR/LF, so nothing can inject headers.
 */
final class Response
{
    /** @var array<string,string> */
    private array $headers = [];

    /** A response with a body and status. Prefer html() or redirect(). */
    public function __construct(private string $body = '', private int $status = 200)
    {
    }

    /** An HTML response. $body must already be escaped (rendered by View). */
    public static function html(string $body, int $status = 200): self
    {
        $response = new self($body, $status);
        $response->header('Content-Type', 'text/html; charset=UTF-8');
        return $response;
    }

    /**
     * Redirect to a path inside the app.
     *
     * @param string $path Must start with a single "/" (an app path, before
     *                     the base path is added). Anything else falls back to "/".
     */
    public static function redirect(string $path, int $status = 303): self
    {
        if (!preg_match('#^/(?![/\\\\])#', $path)) {
            $path = '/';
        }
        $response = new self('', $status);
        $response->header('Location', url($path));
        return $response;
    }

    /** Set a header. Refuses CR/LF to block header injection. */
    public function header(string $name, string $value): self
    {
        if (preg_match('/[\r\n]/', $name . $value)) {
            throw new \InvalidArgumentException('Header injection attempt blocked.');
        }
        $this->headers[$name] = $value;
        return $this;
    }

    /** HTTP status code. */
    public function status(): int
    {
        return $this->status;
    }

    /** Response body. */
    public function body(): string
    {
        return $this->body;
    }

    /** A header value set on this response, or null. */
    public function getHeader(string $name): ?string
    {
        return $this->headers[$name] ?? null;
    }

    /** Send status, headers and body to the client. */
    public function send(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as $name => $value) {
            header($name . ': ' . $value);
        }
        echo $this->body;
    }
}

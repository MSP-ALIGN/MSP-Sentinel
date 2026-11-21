<?php

declare(strict_types=1);

namespace Sentinel\Core;

/**
 * Looks up interface strings in a language file.
 *
 * English source text is the key. lang/<code>.php returns an array that maps
 * source text to the translated text. A missing entry falls back to the
 * English text, so a partial translation never breaks the UI.
 *
 * Security assumptions: language files are trusted code shipped with the app.
 * Output is plain text, and callers escape it.
 */
final class Translator
{
    /** @param array<string,string> $strings */
    private function __construct(private readonly array $strings)
    {
    }

    /** Load a language by code (e.g. "en"). Unknown or invalid codes fall back to English. */
    public static function load(string $code): self
    {
        if (!preg_match('/^[a-z]{2}(_[A-Z]{2})?$/', $code)) {
            $code = 'en';
        }
        $file = SENTINEL_ROOT . '/lang/' . $code . '.php';
        $strings = is_file($file) ? require $file : [];
        return new self(is_array($strings) ? $strings : []);
    }

    /** @param array<string,scalar> $params */
    public function translate(string $text, array $params = []): string
    {
        $out = $this->strings[$text] ?? $text;
        if ($params === []) {
            return $out;
        }
        $replace = [];
        foreach ($params as $key => $value) {
            $replace['{' . $key . '}'] = (string) $value;
        }
        return strtr($out, $replace);
    }
}

<?php

declare(strict_types=1);

/**
 * Small global helpers used by views and controllers.
 *
 * Security assumptions:
 * - e() is the ONLY approved way to print a value into HTML, including
 *   attributes. Every template uses it for every dynamic value.
 * - __() returns plain text, never HTML. Its result must still go through e().
 */

use Sentinel\Core\App;

/**
 * Escape a value for HTML body or attribute context.
 *
 * @param mixed $value Untrusted. Any scalar, null or Stringable.
 * @return string Safe for HTML text and double- or single-quoted attributes.
 */
function e(mixed $value): string
{
    if ($value === null) {
        return '';
    }
    if (is_bool($value)) {
        $value = $value ? '1' : '0';
    }
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
}

/**
 * Translate an interface string.
 *
 * Source strings are English. A language file can map them to another
 * language. Placeholders look like {name} and are replaced with the given
 * values. The values aren't escaped here, because escaping happens at output.
 *
 * @param string               $text   English source text (trusted, written in code).
 * @param array<string,scalar> $params Values for {placeholders}. May be untrusted.
 */
function __(string $text, array $params = []): string
{
    return App::translator()->translate($text, $params);
}

/**
 * Build an application URL, adding the configured base path.
 *
 * @param string               $path  Path starting with "/" (trusted, written in code).
 * @param array<string,scalar> $query Optional query values. They are URL-encoded.
 */
function url(string $path, array $query = []): string
{
    $url = App::basePath() . $path;
    if ($query !== []) {
        $url .= '?' . http_build_query($query);
    }
    return $url;
}

/**
 * URL of a static asset, with the release version appended so browsers
 * fetch fresh files after an upgrade.
 */
function asset(string $path): string
{
    return App::basePath() . '/assets/' . ltrim($path, '/') . '?v=' . rawurlencode(App::version());
}

/**
 * True when the signed-in user holds a permission (1.40), for showing or hiding actions in views. The routes check
 * the same permission again: hiding a button is a convenience, never the protection.
 */
function can(string $permission): bool
{
    return \Sentinel\Core\App::auth()->can($permission);
}

/**
 * The name of a user's or role's role for display (1.40): built-in role names are translated, custom ones shown as
 * typed. Accepts a row with role_name/role_key (a user) or name/role_key (a role). The result still needs e().
 *
 * @param array<string,mixed> $row
 */
function role_label(array $row): string
{
    $name = (string) ($row['role_name'] ?? $row['name'] ?? '');
    return ($row['role_key'] ?? null) !== null ? __($name) : $name;
}

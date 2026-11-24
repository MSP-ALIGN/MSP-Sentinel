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

/**
 * The time zone times are shown in for the signed-in user (1.48): their own choice (My profile), else the
 * organisation's (Settings), else UTC. Times are stored in UTC; only the display changes. Invalid values fall back.
 */
function display_zone(): DateTimeZone
{
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    $names = [];
    try {
        $user = App::auth()->user();
        $names[] = (string) ($user['timezone'] ?? '');
    } catch (\Throwable) {
        // no session (worker, CLI): the organisation's zone
    }
    try {
        $names[] = App::settings()->get('display_timezone');
    } catch (\Throwable) {
        // no database yet
    }
    foreach ($names as $name) {
        if ($name !== '' && in_array($name, DateTimeZone::listIdentifiers(), true)) {
            return $cache = new DateTimeZone($name);
        }
    }
    return $cache = new DateTimeZone('UTC');
}

/**
 * A stored UTC time ('Y-m-d H:i:s') shown in the viewer's time zone with its abbreviation, e.g. "2026-11-24 13:33 PST"
 * (1.48). $zone: another zone (a client's, in reports). Null or empty gives $empty; a value that isn't a date and time
 * is returned as it is. Plain text: print it with e().
 */
function when(?string $utc, ?DateTimeZone $zone = null, string $empty = '–', bool $seconds = false): string
{
    if ($utc === null || trim($utc) === '') {
        return $empty;
    }
    if (preg_match('/^\d{4}-\d\d-\d\d[ T]\d\d:\d\d(:\d\d)?$/', trim($utc)) !== 1) {
        return $utc;
    }
    try {
        $t = new DateTimeImmutable(trim($utc), new DateTimeZone('UTC'));
    } catch (\Exception) {
        return $utc;
    }
    return $t->setTimezone($zone ?? display_zone())->format($seconds ? 'Y-m-d H:i:s T' : 'Y-m-d H:i T');
}

/** The viewer's time zone abbreviation now (for table headings: "Time (PST)"). */
function tz_label(?DateTimeZone $zone = null): string
{
    return (new DateTimeImmutable('now', $zone ?? display_zone()))->format('T');
}


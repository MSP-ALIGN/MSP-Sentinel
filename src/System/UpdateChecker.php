<?php

declare(strict_types=1);

namespace Sentinel\System;

use Sentinel\Core\Settings;

/**
 * Checks once a day whether a newer release exists (one HTTPS GET to the
 * releases feed, config updates.url). Admins can turn it off.
 *
 * Installs made with the one-line installer also know their branch and commit
 * (the BUILD file). For those, the same check asks GitHub's compare API how
 * many commits the branch has moved on since the installed commit (one more
 * GET, config updates.compare_url), so development and production servers
 * that follow a branch see that an update is waiting.
 *
 * Security assumptions:
 * - Nothing is sent but the request itself (no client data, no version in
 *   the User-Agent). TLS is verified; only https (plain http only in the
 *   test suite). Redirects are not followed; the answer is capped at 256 KB.
 * - The response is untrusted: only a version number matching x.y.z is kept.
 *   No URL from the response is stored or shown. From the compare answer only
 *   a commit count (an integer) and a hex commit ID are kept.
 * - The compare URL is built from the BUILD file, whose values App::build()
 *   has already checked against strict patterns; each part is URL-encoded.
 */
final class UpdateChecker
{
    /** The HTTP status of the last request (0: no answer), so a failed check can say why (1.55.2). */
    private int $lastStatus = 0;

    public const DEFAULT_URL = 'https://api.github.com/repos/msp-align/msp-sentinel/releases/latest';
    public const DEFAULT_COMPARE_URL = 'https://api.github.com/repos/{repo}/compare/{base}...{head}';

    /**
     * @param bool $allowHttp Test suite only.
     * @param array{branch:string,sha:string,repo:string}|null $build From App::build(); null for release-archive installs.
     */
    public function __construct(private readonly Settings $settings, private readonly string $url, private readonly string $current, private readonly bool $allowHttp = false,
        private readonly ?array $build = null, private readonly string $compareUrl = self::DEFAULT_COMPARE_URL)
    {
    }

    /** Check if due (or $force). Returns the latest version seen, or null if the check is off or failed. */
    public function check(bool $force = false): ?string
    {
        if ($this->settings->get('update_check_enabled') !== '1') {
            return null;
        }
        $last = $this->settings->get('update_checked_at');
        if (!$force && $last !== '' && strtotime($last . ' UTC') > time() - 20 * 3600) {
            return $this->settings->get('update_latest_version') ?: null;
        }
        $this->settings->set('update_checked_at', gmdate('Y-m-d H:i:s')); // also on failure, so a down feed isn't retried every minute
        $this->checkBranch();
        $body = $this->get($this->url);
        if ($body === null) {
            // 1.55.2: say why. GitHub answers 404 when no release is published yet (or the repository is private).
            $this->settings->set('update_last_error', $this->lastStatus === 404 ? 'no_release' : 'unreachable');
            return null;
        }
        $data = json_decode($body, true);
        $tag = is_array($data) && is_string($data['tag_name'] ?? null) ? $data['tag_name'] : '';
        if (!preg_match('/^v?(\d{1,4}\.\d{1,4}\.\d{1,4})$/', $tag, $m) || (($data['prerelease'] ?? false) === true) || (($data['draft'] ?? false) === true)) {
            $this->settings->set('update_last_error', 'no_release'); // no usable release (e.g. a pre-release only)
            return null;
        }
        $this->settings->set('update_last_error', '');
        $this->settings->set('update_latest_version', $m[1]);
        return $m[1];
    }

    /**
     * How far the followed branch has moved on since the installed commit, or null when unknown
     * (release install, check off, or no answer yet).
     *
     * @return array{branch:string, behind:int, head:string, checked_at:string}|null
     */
    public function branchStatus(): ?array
    {
        $behind = $this->settings->get('update_branch_behind');
        if ($this->build === null || $this->build['repo'] === '' || $this->settings->get('update_check_enabled') !== '1' || !ctype_digit($behind)
            || $this->settings->get('update_branch_base') !== $this->build['sha']) {
            return null; // nothing known for THIS commit (e.g. just updated): wait for the next check
        }
        return ['branch' => $this->build['branch'], 'behind' => (int) $behind, 'head' => $this->settings->get('update_branch_head'), 'checked_at' => $this->settings->get('update_checked_at')];
    }

    /** Compare the installed commit with the branch head (git-based installs only). Failures leave the old answer. */
    private function checkBranch(): void
    {
        if ($this->build === null || $this->build['repo'] === '') {
            return;
        }
        $url = strtr($this->compareUrl, ['{repo}' => implode('/', array_map('rawurlencode', explode('/', $this->build['repo']))),
            '{base}' => rawurlencode($this->build['sha']), '{head}' => rawurlencode($this->build['branch'])]);
        $body = $this->get($url);
        $data = $body === null ? null : json_decode($body, true);
        if (!is_array($data) || !is_int($data['ahead_by'] ?? null) || $data['ahead_by'] < 0) {
            return;
        }
        // ahead_by = commits on the branch that the installed commit doesn't have.
        $commits = is_array($data['commits'] ?? null) ? $data['commits'] : [];
        $last = end($commits);
        // The compare API lists at most 250 commits: further behind, the last one listed is not the branch head.
        $head = $data['ahead_by'] <= 250 && is_array($last) && is_string($last['sha'] ?? null) && preg_match('/^[0-9a-f]{40}$/', $last['sha']) === 1 ? substr($last['sha'], 0, 12) : '';
        $this->settings->set('update_branch_behind', (string) min($data['ahead_by'], 100000));
        $this->settings->set('update_branch_head', $head);
        $this->settings->set('update_branch_base', $this->build['sha']);
    }

    /** One capped, verified GET; the body, or null on any failure. */
    private function get(string $url): ?string
    {
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if ($scheme !== 'https' && !($this->allowHttp && $scheme === 'http')) {
            return null;
        }
        $ch = curl_init($url);
        $body = '';
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_WRITEFUNCTION => static function ($c, string $chunk) use (&$body): int {
                $body .= $chunk;
                return strlen($body) > 262144 ? 0 : strlen($chunk);
            },
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | ($this->allowHttp ? CURLPROTO_HTTP : 0),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'MSP-Sentinel',
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        $this->lastStatus = $ok === false ? 0 : $status;
        return $ok === false || $status !== 200 ? null : $body;
    }

    /** The newer version, if one is known and newer than this install. */
    public function newer(): ?string
    {
        $latest = $this->settings->get('update_latest_version');
        return $this->settings->get('update_check_enabled') === '1' && $latest !== '' && version_compare($latest, $this->current, '>') ? $latest : null;
    }
}

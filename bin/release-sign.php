<?php

declare(strict_types=1);

/**
 * Release signing for agent updates (the MAINTAINER runs this on their own computer, never on a server).
 *
 *   php bin/release-sign.php keygen --out ~/sentinel-release.key
 *       Once: creates the release key pair. The secret key goes to the file you name (0600) and stays with you,
 *       offline if you can; never commit it, never copy it to a server. The public key is printed: put it in
 *       install/release-key.pub and commit that. Agents installed (or upgraded by hand) after that pin it.
 *   php bin/release-sign.php sign --key ~/sentinel-release.key
 *       For each release, after the last code change: writes release/agent-manifest.json (every agent file and its
 *       SHA-256: what `git archive HEAD` contains, without config/, tests/ and the like) and release/agent-manifest.sig.
 *       Commit both with the release.
 *   php bin/release-sign.php verify
 *       Checks release/agent-manifest.* against install/release-key.pub and the files in this folder.
 *
 * Why: agents install new code only when it is signed with this key. Sentinel can tell an agent to update, but can't
 * vouch for code, so a compromised Sentinel server can't push code to client networks.
 *
 * Security assumptions: the secret key is read from a file you choose and only used in memory; it is never printed or
 * written anywhere else. The manifest only lists files of the release archive (no untracked, ignored or export-ignore
 * files).
 */

require dirname(__DIR__) . '/src/System/ReleaseManifest.php';

use Sentinel\System\ReleaseManifest;

if (PHP_SAPI !== 'cli') {
    exit(1);
}
$root = dirname(__DIR__);
$argv = $_SERVER['argv'] ?? [];
$command = $argv[1] ?? 'help';
$opt = static function (string $name) use ($argv): string {
    $i = array_search('--' . $name, $argv, true);
    return $i !== false && isset($argv[$i + 1]) ? (string) $argv[$i + 1] : '';
};
$fail = static function (string $msg): never {
    fwrite(STDERR, $msg . "\n");
    exit(1);
};
$expand = static fn (string $p): string => str_starts_with($p, '~/') ? rtrim((string) getenv('HOME'), '/') . substr($p, 1) : $p;

switch ($command) {
    case 'keygen':
        $out = $expand($opt('out'));
        if ($out === '') {
            $fail('Usage: php bin/release-sign.php keygen --out ~/sentinel-release.key');
        }
        if (file_exists($out)) {
            $fail("{$out} already exists. Keep your existing key (agents pin it); move the file away first if you really mean to replace it.");
        }
        if (str_starts_with(realpath(dirname($out)) ?: '', $root)) {
            $fail('Keep the secret key outside the repository folder (it must never be committed).');
        }
        $pair = sodium_crypto_sign_keypair();
        $old = umask(0077);
        file_put_contents($out, base64_encode(sodium_crypto_sign_secretkey($pair)) . "\n");
        umask($old);
        chmod($out, 0600);
        $public = base64_encode(sodium_crypto_sign_publickey($pair));
        echo "Secret key written to {$out} (0600). Keep it safe and offline; never commit it or copy it to a server.\n\n";
        echo "Public key (put this line in install/release-key.pub and commit it):\n{$public}\n";
        exit(0);

    case 'sign':
        $keyFile = $expand($opt('key'));
        if ($keyFile === '' || !is_readable($keyFile)) {
            $fail('Usage: php bin/release-sign.php sign --key ~/sentinel-release.key');
        }
        $public = trim((string) @file_get_contents($root . '/install/release-key.pub'));
        if ($public === '') {
            $fail('install/release-key.pub is missing: run keygen first and commit the public key.');
        }
        $secret = trim((string) file_get_contents($keyFile));
        $version = trim((string) file_get_contents($root . '/VERSION'));
        // Exactly what a release archive contains (`git archive HEAD`: committed files, export-ignore left out), so
        // every Sentinel, installed from a tarball or a checkout, holds every signed file.
        exec('git -C ' . escapeshellarg($root) . ' archive --format=tar HEAD | tar -tf -', $lines, $code);
        if ($code !== 0) {
            $fail('git archive failed: run this inside the repository.');
        }
        exec('git -C ' . escapeshellarg($root) . ' status --porcelain --untracked-files=no', $dirty);
        $dirty = array_values(array_filter($dirty, static fn (string $l): bool => !str_contains($l, 'release/agent-manifest')));
        if ($dirty !== []) {
            $fail("Commit your changes first (the manifest must match committed files):\n" . implode("\n", array_slice($dirty, 0, 10)));
        }
        // The same rule as the System page (ReleaseManifest::releaseFile), so both make the same manifest and hash.
        $paths = array_values(array_filter($lines, static fn (string $l): bool => $l !== '' && !str_ends_with($l, '/') && ReleaseManifest::releaseFile($l)));
        $manifest = ReleaseManifest::build($root, $version, $paths);
        // Say what isn't part of the agent release (excluded folders, hidden files, odd names): a remote update installs
        // exactly the signed files, so anything else disappears from an updated agent.
        $left = array_values(array_filter($paths, static fn (string $p): bool => !isset($manifest['files'][$p]) && !preg_match('#^(config|storage|dist|tests|release)/#', $p)));
        if ($left !== []) {
            echo 'Not in the agent release (hidden files or unusual names): ' . implode(', ', array_slice($left, 0, 20)) . (count($left) > 20 ? ' ...' : '') . "\n";
        }
        $json = ReleaseManifest::canonical($manifest);
        $sig = ReleaseManifest::sign($json, $secret);
        if (!is_array(ReleaseManifest::verify($json, $sig, $public))) {
            $fail('That secret key does not match install/release-key.pub.');
        }
        @mkdir($root . '/release', 0755);
        file_put_contents($root . '/release/agent-manifest.json', $json);
        file_put_contents($root . '/release/agent-manifest.sig', $sig . "\n");
        echo 'Signed agent release ' . $version . ' (' . count($manifest['files']) . " files). Commit release/agent-manifest.json and release/agent-manifest.sig.\n";
        // Published with the release notes: admins compare it with the hash Sentinel's System page shows before signing.
        echo 'Manifest SHA-256 (publish it with the release notes): ' . hash('sha256', ReleaseManifest::canonical($manifest)) . "\n";
        exit(0);

    case 'verify':
        $public = trim((string) @file_get_contents($root . '/install/release-key.pub'));
        $json = (string) @file_get_contents($root . '/release/agent-manifest.json');
        $sig = (string) @file_get_contents($root . '/release/agent-manifest.sig');
        $m = ReleaseManifest::verify($json, $sig, $public);
        if (is_string($m)) {
            $fail('Not valid: ' . $m . '.');
        }
        $bad = [];
        foreach ($m['files'] as $path => $hash) {
            if (!is_file($root . '/' . $path) || hash_file('sha256', $root . '/' . $path) !== $hash) {
                $bad[] = $path;
            }
        }
        if ($bad !== []) {
            $fail('Signed, but these files differ from the signed release: ' . implode(', ', array_slice($bad, 0, 10)));
        }
        echo 'Valid: agent release ' . $m['version'] . ', ' . count($m['files']) . " files, signed with install/release-key.pub, all files match.\n";
        exit(0);

    default:
        echo "Release signing for agent updates (maintainer only):\n  keygen --out FILE   create the release key pair (once)\n  sign --key FILE     sign this release\n  verify              check the signed release\n";
        exit($command === 'help' ? 0 : 2);
}

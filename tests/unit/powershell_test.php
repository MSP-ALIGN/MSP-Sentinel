<?php

declare(strict_types=1);

/**
 * Static checks for the repository's PowerShell scripts (1.45.2). The test suite has no PowerShell, so a script that
 * doesn't even parse (1.45.1: an unclosed string in install-agent.ps1 broke the Windows agent install) would ship
 * unnoticed. This small lexer follows PowerShell's quoting closely enough to catch the mistakes that matter:
 * strings that never close, unbalanced () and {}, and characters Windows PowerShell 5.1 treats as quotes.
 *
 * Untrusted: nothing (reads files from this repository only). It is a guard, not a full parser.
 */

use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

/**
 * Lex a PowerShell script. Returns a list of problems ("line N: ..."), empty when the quoting and brackets balance.
 *
 * Handles: # and <# #> comments, '...' ('' escape), "..." (backtick and "" escapes, $( ) subexpressions with nested
 * strings), @'...'@ and @"..."@ here-strings, and backtick escapes in code. Any character outside ASCII is reported:
 * Windows PowerShell 5.1 reads curly quotes as real quotes, and a script fetched with Invoke-RestMethod may be decoded
 * in another code page.
 *
 * @return list<string>
 */
$lexPowerShell = static function (string $src): array {
    $problems = [];
    $len = strlen($src);
    $line = 1;
    foreach (explode("\n", $src) as $n => $text) {
        if (preg_match('/[^\x00-\x7F]/', $text)) {
            $problems[] = 'line ' . ($n + 1) . ': a character outside ASCII (Windows PowerShell may read it as a quote)';
        }
    }
    // A stack of open contexts: 'code' (with the bracket that opened it), 'dq' (double-quoted string).
    $stack = [['code', '', 1]];
    $i = 0;
    while ($i < $len) {
        $c = $src[$i];
        $top = end($stack);
        if ($c === "\n") {
            $line++;
        }
        if ($top[0] === 'dq') {
            if ($c === '`') {
                $line += ($src[$i + 1] ?? '') === "\n" ? 1 : 0;
                $i += 2;
                continue;
            }
            if ($c === '"') {
                if (($src[$i + 1] ?? '') === '"') {
                    $i += 2; // "" inside a string is one quote
                    continue;
                }
                array_pop($stack);
                $i++;
                continue;
            }
            if ($c === '$' && ($src[$i + 1] ?? '') === '(') {
                $stack[] = ['code', '(', $line]; // a subexpression: code until its ")"
                $i += 2;
                continue;
            }
            $i++;
            continue;
        }
        // Code.
        if ($c === '`') {
            $line += ($src[$i + 1] ?? '') === "\n" ? 1 : 0;
            $i += 2;
            continue;
        }
        if ($c === '<' && ($src[$i + 1] ?? '') === '#') {
            $end = strpos($src, '#>', $i + 2);
            if ($end === false) {
                $problems[] = "line {$line}: a <# comment is never closed";
                break;
            }
            $line += substr_count($src, "\n", $i, $end - $i);
            $i = $end + 2;
            continue;
        }
        if ($c === '#') {
            $end = strpos($src, "\n", $i);
            $i = $end === false ? $len : $end;
            continue;
        }
        if ($c === '@' && (($src[$i + 1] ?? '') === '"' || ($src[$i + 1] ?? '') === "'") && preg_match('/\G[ \t]*\r?\n/', $src, $m, 0, $i + 2)) {
            $q = $src[$i + 1];
            if (!preg_match('/\n' . preg_quote($q, '/') . '@/', $src, $m, PREG_OFFSET_CAPTURE, $i + 2)) {
                $problems[] = "line {$line}: a here-string is never closed";
                break;
            }
            $end = (int) $m[0][1] + 3;
            $line += substr_count($src, "\n", $i, $end - $i);
            $i = $end;
            continue;
        }
        if ($c === "'") {
            $j = $i + 1;
            while (true) {
                $k = strpos($src, "'", $j);
                if ($k === false) {
                    $problems[] = "line {$line}: a '...' string is never closed";
                    break 2;
                }
                if (($src[$k + 1] ?? '') === "'") {
                    $j = $k + 2; // '' inside a string is one quote
                    continue;
                }
                break;
            }
            $line += substr_count($src, "\n", $i, $k - $i);
            $i = $k + 1;
            continue;
        }
        if ($c === '"') {
            $stack[] = ['dq', '"', $line];
            $i++;
            continue;
        }
        if ($c === '(' || $c === '{') {
            $stack[] = ['code', $c, $line];
            $i++;
            continue;
        }
        if ($c === ')' || $c === '}') {
            $want = $c === ')' ? '(' : '{';
            if ($top[1] !== $want) {
                $problems[] = "line {$line}: \"{$c}\" does not match " . ($top[1] === '' ? 'anything' : "\"{$top[1]}\" from line {$top[2]}");
                break;
            }
            array_pop($stack);
            $i++;
            continue;
        }
        $i++;
    }
    if ($problems === [] && count($stack) > 1) {
        $top = end($stack);
        $problems[] = 'line ' . $top[2] . ': ' . ($top[0] === 'dq' ? 'a "..." string is never closed' : "\"{$top[1]}\" is never closed");
    }
    return $problems;
};

return [
    'PowerShell lexer: catches unclosed strings and brackets, accepts valid quoting' => function (TestContext $ctx) use ($lexPowerShell): void {
        // The 1.45.1 bug: the string ends with an escaped quote and never closes.
        $bad = "@(\n    'a'\n    \"extension_dir = `\"\$PhpDir\\ext`\"\n    'b'\n) | Out-Null\nSay \"PHP \$v installed\"\n";
        Assert::true($lexPowerShell($bad) !== [], 'unclosed string found');
        $good = "@(\n    'a'\n    \"extension_dir = `\"\$PhpDir\\ext`\"\"\n    'it''s'\n) | Out-Null\n"
            . "# a comment with \" and ' and (\n<# block \" comment #>\n"
            . "Fail \"\$([IO.Path]::GetFileName(\$File)) is \"\"quoted\"\" (exit \$(\$p.ExitCode)).\"\n"
            . "\$h = @\"\nraw \" text (\n\"@\n\$s = @'\nraw ' text {\n'@\n& cmd.exe /c \"`\"\$Path`\"\" | Out-Null\n";
        Assert::same([], $lexPowerShell($good), 'valid quoting accepted');
        Assert::true($lexPowerShell("if (\$a) {\n  'x'\n") !== [], 'unclosed brace found');
        Assert::true($lexPowerShell("Say \"\u{201C}quoted\u{201D}\"\n") !== [], 'curly quotes reported');
    },
    'PowerShell scripts in the repository: quoting and brackets balance (they parse)' => function (TestContext $ctx) use ($lexPowerShell): void {
        $root = dirname(__DIR__, 2);
        $files = array_merge(glob($root . '/*.ps1') ?: [], glob($root . '/{agent,bin,docker,scripts}/**/*.ps1', GLOB_BRACE) ?: []);
        Assert::true(in_array($root . '/install-agent.ps1', $files, true), 'install-agent.ps1 is checked');
        foreach ($files as $f) {
            Assert::same([], $lexPowerShell((string) file_get_contents($f)), basename($f));
        }
    },
];

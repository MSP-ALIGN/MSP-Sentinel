<?php

declare(strict_types=1);

namespace Sentinel\Core;

/**
 * Renders PHP templates from the views/ directory.
 *
 * Security assumptions:
 * - Template names are written in code, never taken from input, and are
 *   still checked against a strict pattern so they can't escape views/.
 * - Templates must print every dynamic value with e(). Data passed in is
 *   treated as untrusted.
 */
final class View
{
    /**
     * Render a template inside a layout.
     *
     * @param string              $template Name like "users/index".
     * @param array<string,mixed> $data     Variables for the template (untrusted values allowed).
     * @param string|null         $layout   Layout name ("app", "auth") or null for none.
     */
    public static function render(string $template, array $data = [], ?string $layout = 'app'): string
    {
        $content = self::renderFile($template, $data);
        if ($layout === null) {
            return $content;
        }
        return self::renderFile('layout/' . $layout, $data + ['content' => $content]);
    }

    /**
     * Render one template file in an isolated scope.
     *
     * @param array<string,mixed> $data
     */
    private static function renderFile(string $template, array $data): string
    {
        if (!preg_match('#^[a-z0-9_]+(/[a-z0-9_]+)*$#', $template)) {
            throw new \InvalidArgumentException('Invalid template name.');
        }
        $file = SENTINEL_ROOT . '/views/' . $template . '.php';
        if (!is_file($file)) {
            throw new \RuntimeException('Template not found: ' . $template);
        }
        // A closure keeps the template's variables away from this class.
        $render = static function (string $__file, array $__data): string {
            extract($__data, EXTR_SKIP);
            ob_start();
            try {
                require $__file;
                return (string) ob_get_clean();
            } catch (\Throwable $ex) {
                ob_end_clean();
                throw $ex;
            }
        };
        return $render($file, $data);
    }
}

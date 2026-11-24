<?php

declare(strict_types=1);

/**
 * Mock XposedOrNot API for the breach monitoring tests (included by feeds_router.php for /xon/...). Never used in
 * production. Made-up addresses on *.example domains only.
 *
 * - POST /xon/v1/domain-breaches/ with header x-api-key: the answer is read from xon-domain-breaches.json in the
 *   FEEDS_LOG folder (written by the test), shaped like the real API's: {"status","metrics":{...}}. A wrong key gets
 *   401 {"detail": "Invalid or missing API key"}; xon-mode.txt containing "429" or "garbage" forces those answers.
 * Each call is counted in xon-calls.log (never the key).
 */

$dir = dirname((string) getenv('FEEDS_LOG'));
$sub = substr($path, strlen('/xon'));
file_put_contents($dir . '/xon-calls.log', $_SERVER['REQUEST_METHOD'] . ' ' . $sub . "\n", FILE_APPEND);
$mode = trim((string) @file_get_contents($dir . '/xon-mode.txt'));
if ($sub !== '/v1/domain-breaches/' || $_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['detail' => 'Method not allowed. Use POST /v1/domain-breaches/ with x-api-key header.']);
    exit;
}
if (($_SERVER['HTTP_X_API_KEY'] ?? '') !== 'xon-test-key-0123456789abcdef') {
    http_response_code(401);
    echo json_encode(['detail' => 'Invalid or missing API key']);
    exit;
}
if ($mode === '429') {
    http_response_code(429);
    header('Retry-After: 3600');
    echo json_encode(['detail' => ['error' => 'Rate limit exceeded', 'retry_after' => 3600]]);
    exit;
}
if ($mode === 'garbage') {
    echo '<html>oops</html>';
    exit;
}
echo (string) (@file_get_contents($dir . '/xon-domain-breaches.json') ?: json_encode(['status' => 'success', 'metrics' => ['Breaches_Details' => [], 'Detailed_Breach_Info' => [], 'Domain_Summary' => []]]));
exit;

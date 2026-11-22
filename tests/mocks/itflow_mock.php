<?php

declare(strict_types=1);

/**
 * Mock ITFlow API v1 for tests (included by feeds_router.php for /itflow/...). Never used in production. The client
 * list comes from itflow-clients.json next to the request log (tests change it between syncs); shapes follow ITFlow's
 * api/v1/clients/read.php and read_output.php. The key is "itflow-test-key-0123456789abcdef" in X-API-Key.
 */

$sub = substr($path, strlen('/itflow'));
if (($_SERVER['HTTP_X_API_KEY'] ?? '') !== 'itflow-test-key-0123456789abcdef') {
    http_response_code(401);
    exit;
}
if ($sub === '/api/v1/clients/read.php') {
    $file = dirname((string) getenv('FEEDS_LOG')) . '/itflow-clients.json';
    $all = json_decode((string) @file_get_contents($file), true) ?: [];
    $limit = max(1, (int) ($_GET['limit'] ?? 50));
    $offset = max(0, (int) ($_GET['offset'] ?? 0));
    $rows = array_slice($all, $offset, $limit);
    echo json_encode($rows === [] ? ['success' => 'False', 'message' => 'No resource (for this client and company) with the specified parameter(s).']
        : ['success' => 'True', 'count' => count($rows), 'data' => $rows]);
    exit;
}
http_response_code(404);
echo json_encode(['success' => 'False', 'message' => 'Not found']);
exit;

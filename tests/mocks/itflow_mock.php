<?php

declare(strict_types=1);

/**
 * Mock ITFlow API v1 for tests (included by feeds_router.php for /itflow/...). Never used in production. The client
 * list comes from itflow-clients.json next to the request log (tests change it between syncs); shapes follow ITFlow's
 * api/v1/clients/read.php and read_output.php. The key is "itflow-test-key-0123456789abcdef" in X-API-Key.
 * Tickets and replies (api/v1/tickets/create.php, ticket_replies/create.php) are recorded in itflow-tickets.json so
 * tests can read what Sentinel sent.
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
$store = dirname((string) getenv('FEEDS_LOG')) . '/itflow-tickets.json';
$body = json_decode((string) file_get_contents('php://input'), true) ?: [];
$state = json_decode((string) @file_get_contents($store), true) ?: ['tickets' => [], 'replies' => []];
if ($sub === '/api/v1/tickets/create.php' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $clients = array_column(json_decode((string) @file_get_contents(dirname((string) getenv('FEEDS_LOG')) . '/itflow-clients.json'), true) ?: [], 'client_id');
    if (!in_array((int) ($body['client_id'] ?? 0), array_map('intval', $clients), true) || ($body['ticket_subject'] ?? '') === ''
        || !in_array($body['ticket_priority'] ?? '', ['Low', 'Medium', 'High', 'Urgent'], true)) {
        http_response_code(400);
        echo json_encode(['success' => 'False', 'message' => 'Bad ticket request']);
        exit;
    }
    $id = 5000 + count($state['tickets']) + 1;
    $state['tickets'][] = ['id' => $id] + $body;
    file_put_contents($store, json_encode($state));
    echo json_encode(['success' => 'True', 'count' => '1', 'data' => [['insert_id' => $id]], 'ticket_reference' => 'TCK-' . $id,
        'ticket_url' => 'http://' . $_SERVER['HTTP_HOST'] . '/itflow/agent/ticket.php?ticket_id=' . $id]);
    exit;
}
if ($sub === '/api/v1/ticket_replies/create.php' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $state['replies'][] = $body;
    file_put_contents($store, json_encode($state));
    echo json_encode(['success' => 'True', 'count' => '1', 'data' => [['insert_id' => count($state['replies'])]]]);
    exit;
}
http_response_code(404);
echo json_encode(['success' => 'False', 'message' => 'Not found']);
exit;

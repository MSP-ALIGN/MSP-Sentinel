<?php

declare(strict_types=1);

/**
 * Mock ITFlow API v1 for tests (included by feeds_router.php for /itflow/...). Never used in production. The client
 * list comes from itflow-clients.json next to the request log (tests change it between syncs); shapes follow ITFlow's
 * api/v1/clients/read.php and read_output.php. The key is "itflow-test-key-0123456789abcdef" in X-API-Key.
 * Tickets and replies (api/v1/tickets/create.php, ticket_replies/create.php) are recorded in itflow-tickets.json so
 * tests can read what Sentinel sent, and set a ticket's "status" (open, resolved, closed, deleted) as a tech would.
 * tickets/read.php, resolve.php and reopen.php behave as ITFlow's do: a closed ticket takes no replies and can't be
 * reopened (400). Like ITFlow, create answers ticket_url as the guest link with a secret url_key (Sentinel must not
 * keep it). itflow-fail.json makes it misbehave on purpose: {"refuse_clients":[id]} answers 400 to creates for those
 * clients; {"create_502": true} saves the ticket but answers 502 (an unclear answer).
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
$fail = json_decode((string) @file_get_contents(dirname((string) getenv('FEEDS_LOG')) . '/itflow-fail.json'), true) ?: [];
$save = static function () use (&$state, $store): void {
    file_put_contents($store, json_encode($state));
};
$refuse = static function (string $msg): never {
    http_response_code(400);
    echo json_encode(['success' => 'False', 'message' => $msg]);
    exit;
};
$find = static function (int $id) use (&$state): ?int {
    foreach ($state['tickets'] as $i => $t) {
        if ((int) $t['id'] === $id && ($t['status'] ?? 'open') !== 'deleted') {
            return $i;
        }
    }
    return null;
};
// Service boards of the MountaineerIT build (1.44: mit_boards/read.php and move.php). {"no_boards": true} in
// itflow-fail.json answers 404 like stock ITFlow; {"move_refused": true} refuses moves (409). Moves are recorded in
// itflow-tickets.json ("moves").
if (str_starts_with($sub, '/api/v1/mit_boards/')) {
    if (($fail['no_boards'] ?? false) === true) {
        http_response_code(404);
        echo '<html>Not Found</html>';
        exit;
    }
    $boards = [['board_id' => 1, 'board_name' => 'General', 'board_is_default' => 1], ['board_id' => 3, 'board_name' => 'Alerts', 'board_is_default' => 0],
               ['board_id' => 5, 'board_name' => 'Projects', 'board_is_default' => 0]];
    if ($sub === '/api/v1/mit_boards/read.php') {
        echo json_encode(['success' => 'True', 'count' => count($boards), 'total' => count($boards), 'data' => $boards]);
        exit;
    }
    if ($sub === '/api/v1/mit_boards/move.php' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        if (($fail['move_refused'] ?? false) === true) {
            http_response_code(409);
            echo json_encode(['success' => 'False', 'message' => 'Ticket is not open']);
            exit;
        }
        $i = $find((int) ($body['ticket_id'] ?? 0));
        if ($i === null || !in_array((int) ($body['board_id'] ?? 0), array_column($boards, 'board_id'), true)) {
            http_response_code(404);
            echo json_encode(['success' => 'False', 'message' => 'Ticket or board not found']);
            exit;
        }
        $state['tickets'][$i]['board_id'] = (int) $body['board_id'];
        $state['moves'][] = $body;
        $save();
        echo json_encode(['success' => 'True', 'message' => 'Moved', 'count' => 1, 'data' => [['board_id' => (int) $body['board_id'], 'board_name' => 'x', 'ticket_assigned_to' => 0]]]);
        exit;
    }
}
if ($sub === '/api/v1/tickets/create.php' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $clients = array_column(json_decode((string) @file_get_contents(dirname((string) getenv('FEEDS_LOG')) . '/itflow-clients.json'), true) ?: [], 'client_id');
    if (!in_array((int) ($body['client_id'] ?? 0), array_map('intval', $clients), true) || ($body['ticket_subject'] ?? '') === ''
        || !in_array($body['ticket_priority'] ?? '', ['Low', 'Medium', 'High', 'Urgent'], true)) {
        $refuse('Bad ticket request');
    }
    if (in_array((int) $body['client_id'], array_map('intval', $fail['refuse_clients'] ?? []), true)) {
        $refuse('Client not found');
    }
    $id = 5000 + count($state['tickets']) + 1;
    $state['tickets'][] = ['id' => $id, 'status' => 'open', 'created_at' => gmdate('Y-m-d H:i:s')] + $body;
    $save();
    if (!empty($fail['create_502'])) {
        http_response_code(502);
        echo 'Bad Gateway';
        exit;
    }
    echo json_encode(['success' => 'True', 'count' => '1', 'data' => [['insert_id' => $id]], 'ticket_reference' => 'TCK-' . $id,
        'ticket_url' => 'http://' . $_SERVER['HTTP_HOST'] . '/itflow/guest/guest_view_ticket.php?ticket_id=' . $id . '&url_key=SECRETKEY' . $id]);
    exit;
}
if ($sub === '/api/v1/ticket_replies/create.php' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $i = $find((int) ($body['ticket_id'] ?? 0));
    if ($i === null) {
        echo json_encode(['success' => 'False', 'message' => 'No ticket']);
        exit;
    }
    if ($state['tickets'][$i]['status'] === 'closed') {
        $refuse('That ticket is closed');
    }
    $state['replies'][] = $body;
    $save();
    echo json_encode(['success' => 'True', 'count' => '1', 'data' => [['insert_id' => count($state['replies'])]]]);
    exit;
}
if ($sub === '/api/v1/tickets/read.php') {
    $row = static fn (array $t): array => ['ticket_id' => $t['id'], 'ticket_prefix' => 'TCK-', 'ticket_number' => $t['id'], 'ticket_client_id' => (int) $t['client_id'],
        'ticket_subject' => $t['ticket_subject'], 'ticket_vendor_ticket_number' => $t['ticket_vendor_ticket_number'] ?? '',
        'ticket_created_at' => $t['created_at'] ?? '2026-01-01 00:00:00',
        'ticket_status' => ['open' => 2, 'resolved' => 4, 'closed' => 5][$t['status']] ?? 2,
        'ticket_resolved_at' => in_array($t['status'], ['resolved', 'closed'], true) ? '2026-11-20 10:00:00' : null,
        'ticket_closed_at' => $t['status'] === 'closed' ? '2026-11-20 11:00:00' : null];
    if (isset($_GET['ticket_id'])) {
        $i = $find((int) $_GET['ticket_id']);
        echo json_encode($i === null ? ['success' => 'False', 'message' => 'No resource (for this client and company) with the specified parameter(s).']
            : ['success' => 'True', 'count' => 1, 'data' => [$row($state['tickets'][$i])]]);
        exit;
    }
    $rows = array_values(array_map($row, array_filter($state['tickets'], static fn (array $t): bool => ($t['status'] ?? 'open') !== 'deleted'
        && (!isset($_GET['client_id']) || (int) $t['client_id'] === (int) $_GET['client_id']))));
    $rows = array_slice($rows, max(0, (int) ($_GET['offset'] ?? 0)), max(1, (int) ($_GET['limit'] ?? 50)));
    echo json_encode($rows === [] ? ['success' => 'False', 'message' => 'No resource (for this client and company) with the specified parameter(s).']
        : ['success' => 'True', 'count' => count($rows), 'data' => $rows]);
    exit;
}
if (in_array($sub, ['/api/v1/tickets/resolve.php', '/api/v1/tickets/reopen.php'], true) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $i = $find((int) ($body['ticket_id'] ?? 0));
    if ($i === null || (int) $state['tickets'][$i]['client_id'] !== (int) ($body['client_id'] ?? 0)) {
        echo json_encode(['success' => 'False', 'message' => 'No ticket']);
        exit;
    }
    $cur = $state['tickets'][$i]['status'];
    if ($sub === '/api/v1/tickets/resolve.php' && $cur !== 'open') {
        echo json_encode(['success' => 'False', 'message' => 'Ticket is not open']); // as ITFlow: 200, success False
        exit;
    }
    if ($sub === '/api/v1/tickets/reopen.php' && $cur === 'closed') {
        $refuse('That ticket is closed. Start a new one instead.');
    }
    if ($sub === '/api/v1/tickets/reopen.php' && $cur === 'open') {
        $refuse('That ticket is open already.');
    }
    $state['tickets'][$i]['status'] = $sub === '/api/v1/tickets/resolve.php' ? 'resolved' : 'open';
    $state['log'][] = basename($sub, '.php') . ':' . $state['tickets'][$i]['id'];
    $save();
    echo json_encode(['success' => 'True', 'count' => 1]);
    exit;
}
http_response_code(404);
echo json_encode(['success' => 'False', 'message' => 'Not found']);
exit;

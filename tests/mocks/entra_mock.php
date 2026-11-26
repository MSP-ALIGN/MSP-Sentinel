<?php

declare(strict_types=1);

/**
 * Mock Microsoft Entra ID sign-in for the "Sign in with Microsoft" tests (1.43). Never used in production; made-up
 * tenant, app and accounts only. Included by feeds_router.php for paths under /entra/{tenant}/.
 *
 * - GET  .../oauth2/v2.0/authorize  remembers nonce, PKCE challenge and redirect for a new one-time code and
 *                                   answers 302 to redirect_uri?code=...&state=... (no real sign-in page)
 * - POST .../oauth2/v2.0/token      checks client secret, code, redirect and PKCE verifier, then returns an ID token
 *                                   signed with the mock's own RSA key
 * - GET  .../discovery/v2.0/keys    the mock's public key as a JWK set
 *
 * The test chooses the signed-in account through scenario.json in the state folder (next to FEEDS_LOG): claims to
 * set or override (oid, email, amr, ...), and "tamper" options: wrong_key, wrong_aud, wrong_iss, wrong_tid, expired,
 * wrong_nonce, guest (an idp claim from another directory), stale_mfa (auth_time two hours ago).
 */

$dir = dirname((string) getenv('FEEDS_LOG')) . '/entra';
@mkdir($dir, 0700, true);
$keyFile = $dir . '/key.pem';
if (!is_file($keyFile)) {
    $k = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($k, $pem);
    file_put_contents($keyFile, $pem);
}
$key = openssl_pkey_get_private((string) file_get_contents($keyFile));
$b64 = static fn (string $s): string => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
$path = (string) parse_url((string) $_SERVER['REQUEST_URI'], PHP_URL_PATH);

// "Connect to Microsoft 365" (1.63): the device authorization flow, as Microsoft's public Graph client uses it.
// scenario.json "device": {"pending": n (authorization_pending answers before the token), "slow_down": true (the first
// answer is slow_down), "error": "authorization_declined" | "expired_token" | ... (instead of a token)}.
if (preg_match('#^/entra/organizations/oauth2/v2\.0/(devicecode|token)$#', $path, $dm) === 1) {
    $sc = is_file($dir . '/scenario.json') ? (array) json_decode((string) file_get_contents($dir . '/scenario.json'), true) : [];
    $dev = (array) ($sc['device'] ?? []);
    header('Content-Type: application/json');
    if (($_POST['client_id'] ?? '') !== '14d82eec-204b-4c2f-b7e8-296a70dab67e') {
        http_response_code(400);
        echo json_encode(['error' => 'unauthorized_client']);
        exit;
    }
    if ($dm[1] === 'devicecode') {
        file_put_contents($dir . '/device-request.json', json_encode($_POST));
        $device = 'mock-device-' . bin2hex(random_bytes(8));
        file_put_contents($dir . '/device.json', json_encode(['device_code' => $device, 'polls' => 0]));
        echo json_encode(['device_code' => $device, 'user_code' => 'MOCK1234', 'verification_uri' => 'https://microsoft.com/devicelogin', 'expires_in' => 900, 'interval' => 1,
            'message' => 'To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code MOCK1234 to authenticate.']);
        exit;
    }
    $st = is_file($dir . '/device.json') ? (array) json_decode((string) file_get_contents($dir . '/device.json'), true) : [];
    if (($_POST['grant_type'] ?? '') !== 'urn:ietf:params:oauth:grant-type:device_code' || ($_POST['device_code'] ?? '') !== ($st['device_code'] ?? null)) {
        http_response_code(400);
        echo json_encode(['error' => 'bad_verification_code']);
        exit;
    }
    $st['polls'] = (int) $st['polls'] + 1;
    file_put_contents($dir . '/device.json', json_encode($st));
    http_response_code(400);
    if (!empty($dev['slow_down']) && $st['polls'] === 1) {
        echo json_encode(['error' => 'slow_down']);
        exit;
    }
    if ($st['polls'] <= (int) ($dev['pending'] ?? 0)) {
        echo json_encode(['error' => 'authorization_pending', 'error_description' => 'AADSTS70016: pending. Trace ID: made-up']);
        exit;
    }
    if (isset($dev['error'])) {
        echo json_encode(['error' => (string) $dev['error'], 'error_description' => 'AADSTS made-up description <script>']);
        exit;
    }
    http_response_code(200);
    echo json_encode(['token_type' => 'Bearer', 'access_token' => 'mock-graph-token', 'expires_in' => 3600, 'scope' => (string) ($_POST['scope'] ?? '')]);
    exit;
}
if (preg_match('#^/entra/([0-9a-f-]{36})/(oauth2/v2\.0/authorize|oauth2/v2\.0/token|discovery/v2\.0/keys)$#', $path, $m) !== 1) {
    http_response_code(404);
    echo json_encode(['error' => 'not_found']);
    exit;
}
[$tenant, $what] = [$m[1], $m[2]];
$scenario = is_file($dir . '/scenario.json') ? (array) json_decode((string) file_get_contents($dir . '/scenario.json'), true) : [];

if ($what === 'discovery/v2.0/keys') {
    $d = openssl_pkey_get_details($key)['rsa'];
    echo json_encode(['keys' => [['kty' => 'RSA', 'use' => 'sig', 'kid' => 'mock-key-1', 'n' => $b64($d['n']), 'e' => $b64($d['e'])]]]);
    exit;
}
if ($what === 'oauth2/v2.0/authorize') {
    $code = bin2hex(random_bytes(16));
    file_put_contents($dir . '/code-' . $code . '.json', json_encode(['nonce' => $_GET['nonce'] ?? '', 'challenge' => $_GET['code_challenge'] ?? '',
        'redirect' => $_GET['redirect_uri'] ?? '', 'client' => $_GET['client_id'] ?? '']));
    file_put_contents($dir . '/last-authorize.json', json_encode($_GET));
    header('Location: ' . ($_GET['redirect_uri'] ?? '') . '?' . http_build_query(['code' => $code, 'state' => $_GET['state'] ?? '']));
    http_response_code(302);
    exit;
}
// Token endpoint
$code = preg_replace('/[^0-9a-f]/', '', (string) ($_POST['code'] ?? ''));
$stored = is_file($dir . '/code-' . $code . '.json') ? json_decode((string) file_get_contents($dir . '/code-' . $code . '.json'), true) : null;
@unlink($dir . '/code-' . $code . '.json'); // one use
$verifier = (string) ($_POST['code_verifier'] ?? '');
if (!is_array($stored) || ($_POST['client_secret'] ?? '') !== 'mock-client-secret-value' || ($_POST['redirect_uri'] ?? '') !== $stored['redirect']
    || $b64(hash('sha256', $verifier, true)) !== $stored['challenge'] || ($_POST['client_id'] ?? '') !== $stored['client']) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid_grant']);
    exit;
}
$tamper = (array) ($scenario['tamper'] ?? []);
$now = time();
$claims = array_merge([
    'iss' => 'https://login.microsoftonline.com/' . (in_array('wrong_iss', $tamper, true) ? '11111111-1111-1111-1111-111111111111' : $tenant) . '/v2.0',
    'aud' => in_array('wrong_aud', $tamper, true) ? '22222222-2222-2222-2222-222222222222' : $stored['client'],
    'tid' => in_array('wrong_tid', $tamper, true) ? '33333333-3333-3333-3333-333333333333' : $tenant,
    'iat' => $now - 5, 'nbf' => $now - 5, 'exp' => in_array('expired', $tamper, true) ? $now - 3600 : $now + 3600,
    'nonce' => in_array('wrong_nonce', $tamper, true) ? 'not-the-nonce' : $stored['nonce'],
    'oid' => '0d1e2f3a-4b5c-4d6e-8f70-819203a4b5c6', 'name' => 'Example User', 'email' => 'user@msp.example', 'amr' => ['pwd', 'mfa'],
    'auth_time' => in_array('stale_mfa', $tamper, true) ? $now - 7200 : $now - 5,
], in_array('guest', $tamper, true) ? ['idp' => 'https://sts.windows.net/44444444-4444-4444-4444-444444444444/'] : [], (array) ($scenario['claims'] ?? []));
$header = $b64(json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'mock-key-1']));
$body = $b64(json_encode($claims));
$signer = $key;
if (in_array('wrong_key', $tamper, true)) {
    $signer = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
}
openssl_sign($header . '.' . $body, $sig, $signer, OPENSSL_ALGO_SHA256);
echo json_encode(['token_type' => 'Bearer', 'id_token' => $header . '.' . $body . '.' . $b64($sig), 'access_token' => 'mock-access-token', 'expires_in' => 3600]);
exit;

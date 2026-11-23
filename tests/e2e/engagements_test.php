<?php

declare(strict_types=1);

/**
 * End-to-end tests for pen-test engagements (1.27, part 1): created with the client's signed authorisation (a PDF),
 * only inside the authorised scope (external) and a site's internal authorisation (internal), approved by a
 * DIFFERENT admin with their password, stopped by the kill switch, cancelled before approval; the gate the scanners
 * use (isActive) and the target checks with exclusions. Roles enforced. Made-up data and documentation ranges only.
 */

use Sentinel\Core\App;
use Sentinel\Engagements\EngagementRepository as ER;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$engSetup = static function (TestContext $ctx): array {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Engagement Example'")->fetchColumn();
    if ($cid === 0) {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Engagement Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $admin->submit('/clients/' . $cid . '/authorisations/new', '/clients/' . $cid . '/authorisations', [
            'approved_by_name' => 'Robin Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'),
            'valid_from' => gmdate('Y-m-d', time() - 86400), 'valid_until' => gmdate('Y-m-d', time() + 86400 * 200),
            'document_ref' => '', 'notes' => '', 'scope' => "203.0.113.0/28\nportal.engagement.example\n", 'confirm' => '1']);
        $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
        $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
            'approved_by_name' => 'Sam Example', 'approved_by_role' => 'IT Manager', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
            'valid_until' => gmdate('Y-m-d', time() + 86400 * 300), 'document_ref' => 'TICKET-9001', 'notes' => '', 'ranges' => '10.97.0.0/24', 'confirm' => '1']);
        foreach (['engtech' => 'technician', 'engadmin2' => 'admin', 'engviewer' => 'viewer'] as $u => $role) {
            if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = '{$u}'")->fetchColumn() === 0) {
                $ctx->createUser($u, $role, ucfirst($u) . '-Pass-0001!');
            }
        }
    }
    $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
    $pdf = dirname($ctx->configPath) . '/signed-authorisation.pdf';
    file_put_contents($pdf, "%PDF-1.4\n% made-up signed authorisation for the test suite\n%%EOF\n");
    return [$cid, $site, $pdf];
};
/** The form fields of a valid engagement (window: an hour ago until tomorrow, in UTC as the client is). */
$fields = static fn (int $site, array $over = []): array => $over + [
    'name' => 'Annual test 2027', 'signer_name' => 'Robin Example', 'signer_role' => 'Owner', 'signed_on' => gmdate('Y-m-d'),
    'window_start' => gmdate('Y-m-d\TH:i', time() - 3600), 'window_end' => gmdate('Y-m-d\TH:i', time() + 86400), 'intensity' => 'normal',
    'tests[0]' => 'tcp_full', 'tests[1]' => 'nse_safe', 'tests[2]' => 'anon_access',
    'external' => "203.0.113.0/29\nportal.engagement.example", 'internal_' . $site => '10.97.0.0/25', 'exclusions' => "203.0.113.5\n10.97.0.9", 'notes' => '', 'confirm' => '1',
];
$lastId = static fn (TestContext $ctx, int $cid): int => (int) $ctx->db->query("SELECT MAX(id) FROM engagements WHERE client_id = {$cid}")->fetchColumn();

return [
    'engagements: only inside the authorised scope, with a signed PDF; roles enforced' => function (TestContext $ctx) use ($engSetup, $fields, $lastId): void {
        [$cid, $site, $pdf] = $engSetup($ctx);
        $tech = $ctx->login('engtech', 'Engtech-Pass-0001!');
        $viewer = $ctx->login('engviewer', 'Engviewer-Pass-0001!');
        Assert::contains('Pen-test engagements', $ctx->clientSection($tech, $cid, 'engagements'));
        Assert::status(403, $viewer->get('/clients/' . $cid . '/engagements/new'), 'viewers cannot create');
        $form = '/clients/' . $cid . '/engagements/new';
        $action = '/clients/' . $cid . '/engagements';
        $before = $lastId($ctx, $cid);
        // Outside the scope (external and internal), not a PDF, no confirmation: refused, nothing saved.
        $res = $tech->upload($form, $action, $fields($site, ['external' => '203.0.113.64/28']), 'document', $pdf, 'application/pdf');
        Assert::status(422, $res);
        Assert::contains('not inside this client', $res->body);
        $res = $tech->upload($form, $action, $fields($site, ['internal_' . $site => '10.98.0.0/24']), 'document', $pdf, 'application/pdf');
        Assert::contains('inside the site', $res->body);
        $txt = dirname($ctx->configPath) . '/not-a-pdf.pdf';
        file_put_contents($txt, 'hello');
        Assert::contains('must be a PDF', $tech->upload($form, $action, $fields($site), 'document', $txt, 'application/pdf')->body);
        Assert::contains('Confirm that the client signed', $tech->upload($form, $action, $fields($site, ['confirm' => '']), 'document', $pdf, 'application/pdf')->body);
        Assert::contains('at most 14 days', $tech->upload($form, $action, $fields($site, ['window_end' => gmdate('Y-m-d\TH:i', time() + 86400 * 20)]), 'document', $pdf, 'application/pdf')->body);
        Assert::same($before, $lastId($ctx, $cid), 'nothing saved');
        // A valid one.
        $res = $tech->upload($form, $action, $fields($site), 'document', $pdf, 'application/pdf');
        Assert::status(303, $res);
        $id = $lastId($ctx, $cid);
        $e = App::engagements()->find($id);
        Assert::same(ER::STATE_AWAITING, ER::state($e, gmdate('Y-m-d H:i:s')));
        Assert::same(hash_file('sha256', $pdf), $e['document_sha256']);
        Assert::same(['tcp_full', 'nse_safe', 'anon_access'], $e['tests_list']);
        Assert::true(!(App::engagements()->isActive($id)), 'nothing runs before approval');
        $page = $tech->get('/engagements/' . $id)->body;
        Assert::contains('Awaiting approval', $page);
        Assert::contains('portal.engagement.example', $page);
        Assert::status(200, $viewer->get('/engagements/' . $id), 'everyone can view');
        // The document: a download, never inline; viewers can't fetch it.
        $doc = $tech->get('/engagements/' . $id . '/document');
        Assert::status(200, $doc);
        Assert::contains('attachment', (string) $doc->header('content-disposition'));
        Assert::contains('sandbox', (string) $doc->header('content-security-policy'));
        Assert::status(403, $viewer->get('/engagements/' . $id . '/document'));
        // Target checks the scanners use: inside, excluded, outside.
        Assert::true(ER::externalAllows($e['targets'], '203.0.113.3'), 'inside');
        Assert::true(!(ER::externalAllows($e['targets'], '203.0.113.5')), 'excluded');
        Assert::true(!(ER::externalAllows($e['targets'], '203.0.113.9')), 'outside the engagement (though inside the scope)');
        Assert::true(ER::externalAllows($e['targets'], 'portal.engagement.example'), 'a named host');
        Assert::true(ER::internalAllows($e['targets'], $site, '10.97.0.20'), 'internal inside');
        Assert::true(!(ER::internalAllows($e['targets'], $site, '10.97.0.9')), 'internal excluded');
        Assert::true(!(ER::internalAllows($e['targets'], $site, '10.97.0.200')), 'internal outside the engagement');
        Assert::true(!(ER::internalAllows($e['targets'], $site + 999, '10.97.0.20')), 'another site');
    },
    'engagements: a different admin approves with their password; stop is final; cancel before approval' => function (TestContext $ctx) use ($engSetup, $fields, $lastId): void {
        [$cid, $site, $pdf] = $engSetup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin2 = $ctx->login('engadmin2', 'Engadmin2-Pass-0001!');
        $tech = $ctx->login('engtech', 'Engtech-Pass-0001!');
        // Created by an admin: that admin can't approve it.
        $admin->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => 'Two-person rule']), 'document', $pdf, 'application/pdf');
        $id = $lastId($ctx, $cid);
        $admin->post('/engagements/' . $id . '/approve', ['_csrf' => $admin->get('/engagements/' . $id)->csrf(), 'password' => 'Admin-Pass-0001!']);
        Assert::same(null, App::engagements()->find($id)['approved_at'], 'never by its creator');
        Assert::status(403, $tech->post('/engagements/' . $id . '/approve', ['_csrf' => $tech->get('/engagements/' . $id)->csrf(), 'password' => 'Engtech-Pass-0001!']), 'technicians cannot approve');
        $admin2->post('/engagements/' . $id . '/approve', ['_csrf' => $admin2->get('/engagements/' . $id)->csrf(), 'password' => 'wrong']);
        Assert::same(null, App::engagements()->find($id)['approved_at'], 'the password is required');
        $admin2->post('/engagements/' . $id . '/approve', ['_csrf' => $admin2->get('/engagements/' . $id)->csrf(), 'password' => 'Engadmin2-Pass-0001!']);
        $e = App::engagements()->find($id);
        Assert::true($e['approved_at'] !== null, 'approved by the second admin');
        Assert::true(App::engagements()->isActive($id), 'active inside its window');
        Assert::contains('Active: testing is allowed now', $tech->get('/engagements/' . $id)->body);
        // The global kill switch also stops it.
        App::settings()->set('scanning_paused', '1');
        Assert::true(!(App::engagements()->isActive($id)), 'global pause');
        App::settings()->set('scanning_paused', '0');
        // Stop: a technician can, with a reason; final.
        $tech->post('/engagements/' . $id . '/stop', ['_csrf' => $tech->get('/engagements/' . $id)->csrf(), 'reason' => '']);
        Assert::true(App::engagements()->isActive($id), 'a reason is required');
        $tech->post('/engagements/' . $id . '/stop', ['_csrf' => $tech->get('/engagements/' . $id)->csrf(), 'reason' => 'Client asked to pause']);
        Assert::true(!(App::engagements()->isActive($id)), 'stopped');
        Assert::true(!(App::engagements()->approve($id, (int) $ctx->db->query("SELECT id FROM users WHERE username = 'engadmin2'")->fetchColumn())), 'never approved again');
        Assert::contains('Client asked to pause', $tech->get('/engagements/' . $id)->body);
        // A future window: approved but scheduled, not active yet.
        $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => 'Next month',
            'window_start' => gmdate('Y-m-d\TH:i', time() + 86400 * 3), 'window_end' => gmdate('Y-m-d\TH:i', time() + 86400 * 5)]), 'document', $pdf, 'application/pdf');
        $later = $lastId($ctx, $cid);
        $admin->post('/engagements/' . $later . '/approve', ['_csrf' => $admin->get('/engagements/' . $later)->csrf(), 'password' => 'Admin-Pass-0001!']);
        Assert::same(ER::STATE_SCHEDULED, ER::state(App::engagements()->find($later), gmdate('Y-m-d H:i:s')));
        Assert::true(!(App::engagements()->isActive($later)), 'not before its window');
        // Cancel: only before approval.
        $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => 'Withdrawn']), 'document', $pdf, 'application/pdf');
        $c = $lastId($ctx, $cid);
        $tech->post('/engagements/' . $c . '/cancel', ['_csrf' => $tech->get('/engagements/' . $c)->csrf()]);
        Assert::same(ER::STATE_CANCELLED, ER::state(App::engagements()->find($c), gmdate('Y-m-d H:i:s')));
        Assert::true(!(App::engagements()->cancel($later)), 'an approved one cannot be cancelled, only stopped');
        $audit = implode("\n", $ctx->db->query("SELECT action FROM audit_log WHERE action LIKE 'engagement.%'")->fetchAll(PDO::FETCH_COLUMN));
        foreach (['engagement.created', 'engagement.approved', 'engagement.stopped', 'engagement.cancelled'] as $a) {
            Assert::contains($a, $audit);
        }
    },
];

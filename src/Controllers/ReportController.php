<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use DateTimeImmutable;
use DateTimeZone;
use Sentinel\Alerts\SmtpMailer;
use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Reports\CsvExport;
use Sentinel\Reports\ReportBuilder;

/**
 * Reports: create, list, view, download (HTML and CSV), delete, plus the
 * monthly schedule per client and the report branding.
 *
 * Access (enforced by the routes): everyone signed in views and downloads
 * saved reports; technicians and admins create them; admins delete them,
 * set monthly schedules and branding.
 *
 * Untrusted: {id}, the kind and period choices (fixed lists), schedule
 * recipients (validated addresses), branding text, colour and logo upload.
 *
 * Security assumptions:
 * - A stored report is served as-is with its own CSP: no scripts at all,
 *   sandboxed, inline styles and data: images only, never framed. Its HTML
 *   was produced by our renderer, which escapes every value.
 * - Downloads use fixed, sanitised file names and nosniff.
 * - Creating, deleting and changing schedules or branding are audited.
 */
final class ReportController extends Controller
{
    /** CSP for stored report documents (stricter than the app's: no scripts, no requests, sandboxed). */
    private const REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox";

    /** Period choices: key => [label, days or 'month']. */
    private const PERIODS = ['30' => 'Last 30 days', 'month' => 'Last calendar month', '90' => 'Last 90 days'];

    /** GET /reports */
    public function index(Request $request): Response
    {
        $clientId = ctype_digit($request->query('client')) ? (int) $request->query('client') : null;
        return $this->page('reports/index', __('Reports'), [
            'reports' => App::reports()->list($clientId, 200, App::auth()->clientIds()),
            'clients' => App::clients()->all(false, App::auth()->clientIds()),
            'clientFilter' => $clientId,
        ]);
    }

    /**
     * POST /reports: the same, from the Reports page with a client picker (1.34). Untrusted: client_id (must be a
     * known client; the store checks archive state as from the client page).
     */
    public function storeFromList(Request $request): Response
    {
        $id = (int) $request->input('client_id');
        if ($id <= 0 || App::clients()->find($id) === null || !App::auth()->canSeeClient($id)) {
            Session::flash('danger', __('Choose a client for the report.'));
            return Response::redirect('/reports');
        }
        return $this->store($request, ['id' => (string) $id]);
    }

    /** POST /clients/{id}/reports: create an executive and/or technical report now. */
    public function store(Request $request, array $params): Response
    {
        $client = $this->client($params);
        $kinds = match ($request->input('kind')) {
            'executive' => ['executive'],
            'technical' => ['technical'],
            'both' => ['executive', 'technical'],
            default => null,
        };
        $period = $request->input('period');
        if ($kinds === null || !array_key_exists($period, self::PERIODS)) {
            Session::flash('danger', __('Choose a report type and period.'));
            return Response::redirect('/clients/' . (int) $client['id'] . '/reports');
        }
        [$start, $end] = self::period($period);
        $user = $this->user();
        $ids = [];
        foreach ($kinds as $kind) {
            try {
                $id = App::reportService()->generate($client, $kind, $start, $end, (int) $user['id'], (string) $user['display_name']);
            } catch (\RuntimeException $ex) {
                Session::flash('danger', $ex->getMessage());
                return Response::redirect('/clients/' . (int) $client['id'] . '/reports');
            }
            $ids[] = $id;
            $this->audit($request, 'report.created', 'report', $id, ['client' => (int) $client['id'], 'kind' => $kind, 'period' => $start . '..' . $end]);
        }
        Session::flash('success', count($ids) === 1 ? __('Report created.') : __('{n} reports created.', ['n' => count($ids)]));
        // From the client's page, stay there (1.34); from the Reports page, show that client's reports.
        return Response::redirect(count($ids) === 1 ? '/reports/' . $ids[0]
            : ($request->input('back') === 'client' ? '/clients/' . (int) $client['id'] . '/reports' : '/reports?client=' . (int) $client['id']));
    }

    /** POST /clients/{id}/report-schedule: monthly reports on/off and their MSP-staff recipients. */
    public function schedule(Request $request, array $params): Response
    {
        $client = $this->client($params);
        $on = $request->input('report_monthly') === '1';
        if ($on && (int) ($client['is_demo'] ?? 0) === 1) {
            Session::flash('info', __('This is a demo client with made-up data: it never emails reports.'));
            return Response::redirect('/clients/' . (int) $client['id'] . '/reports');
        }
        $list = array_values(array_unique(array_filter(array_map('trim', preg_split('/[,;\s]+/', $request->input('report_recipients')) ?: []))));
        if (count($list) > 5 || array_filter($list, static fn (string $a): bool => !SmtpMailer::validAddress($a)) !== []) {
            Session::flash('danger', __('Report recipients: up to 5 valid email addresses, separated by commas.'));
            return Response::redirect('/clients/' . (int) $client['id'] . '/reports');
        }
        if ($on && $list === []) {
            Session::flash('danger', __('To send monthly reports, enter at least one recipient.'));
            return Response::redirect('/clients/' . (int) $client['id'] . '/reports');
        }
        App::db()->prepare('UPDATE clients SET report_monthly = :m, report_recipients = :r, updated_at = UTC_TIMESTAMP() WHERE id = :id')
            ->execute(['m' => $on ? 1 : 0, 'r' => implode(',', $list), 'id' => (int) $client['id']]);
        $this->audit($request, 'client.report_schedule', 'client', (int) $client['id'], ['monthly' => $on, 'recipients' => $list]);
        Session::flash('success', $on ? __('Monthly reports turned on.') : __('Monthly report settings saved.'));
        if ($on && App::settings()->get('email_enabled') !== '1') {
            Session::flash('warning', __('Email alerts are turned off in Settings, so monthly reports will be created but not emailed.'));
        }
        return Response::redirect('/clients/' . (int) $client['id'] . '/reports');
    }

    /** GET /reports/{id}: details and actions. */
    public function show(Request $request, array $params): Response
    {
        $report = $this->report($params);
        $snapshot = json_decode((string) $report['snapshot'], true) ?: [];
        unset($report['html']);
        $rating = $snapshot['rating'] ?? null;
        if (is_string($rating)) {
            // Pen-test reports and retest letters keep the level only.
            $rating = ['level' => $rating, 'reason' => __('{f} Fail(s) and {w} Warning(s) from the engagement\'s tests.', ['f' => (int) ($snapshot['counts']['fail'] ?? 0), 'w' => (int) ($snapshot['counts']['warn'] ?? 0)])];
        }
        return $this->page('reports/show', (string) $report['title'], ['report' => $report, 'counts' => $snapshot['counts'] ?? [], 'rating' => is_array($rating) ? $rating : null]);
    }

    /** GET /reports/{id}/view: the stored document itself, for reading and printing. */
    public function view(Request $request, array $params): Response
    {
        $report = $this->report($params);
        return Response::html($this->readable((string) $report['html']))->header('Content-Security-Policy', self::REPORT_CSP);
    }

    /** GET /reports/{id}/download: the document as a self-contained HTML file. */
    public function download(Request $request, array $params): Response
    {
        $report = $this->report($params);
        return Response::html($this->readable((string) $report['html']))
            ->header('Content-Security-Policy', self::REPORT_CSP)
            ->header('Content-Disposition', 'attachment; filename="' . self::fileName($report, 'html') . '"');
    }

    /** GET /reports/{id}/csv: the report's findings as CSV. */
    public function csv(Request $request, array $params): Response
    {
        $report = $this->report($params);
        $snapshot = json_decode((string) $report['snapshot'], true);
        if (!is_array($snapshot)) {
            throw new HttpException(404);
        }
        return (new Response($this->readable(CsvExport::build($snapshot))))
            ->header('Content-Type', 'text/csv; charset=UTF-8')
            ->header('Content-Security-Policy', "default-src 'none'; sandbox")
            ->header('Content-Disposition', 'attachment; filename="' . self::fileName($report, 'csv') . '"');
    }

    /** A report's text as this user may read it: email addresses masked without "See breached addresses" (1.42.2). */
    private function readable(string $text): string
    {
        return App::auth()->can('breach.addresses') ? $text : \Sentinel\Breach\BreachMonitor::maskAll($text);
    }

    /** POST /reports/{id}/delete */
    public function delete(Request $request, array $params): Response
    {
        $report = $this->report($params);
        App::reports()->delete((int) $report['id']);
        $this->audit($request, 'report.deleted', 'report', (int) $report['id'], ['client' => (int) $report['client_id'], 'title' => $report['title'], 'sha256' => $report['html_sha256']]);
        Session::flash('success', __('Report deleted.'));
        return Response::redirect('/reports');
    }

    /**
     * Branding text fields (1.59): name => [maximum length, multi-line allowed, error message]. Line breaks are kept
     * only where multi-line is allowed; other control characters are always refused. Values are plain text: the
     * report templates escape them, and none is ever used as a link or in a header.
     */
    private const BRAND_TEXT = [
        'brand_name' => [100, false, 'The company name can be up to 100 characters.'],
        'brand_footer' => [500, true, 'The footer note can be up to 500 characters.'],
        'brand_address' => [200, true, 'The address can be up to 200 characters.'],
        'brand_phone' => [40, false, 'The phone number can be up to 40 characters.'],
        'brand_email' => [120, false, 'The email address can be up to 120 characters.'],
        'brand_website' => [120, false, 'The website can be up to 120 characters.'],
        'report_prepared_by' => [100, false, 'The "prepared by" name can be up to 100 characters.'],
        'report_prepared_title' => [100, false, 'The job title can be up to 100 characters.'],
        'report_signoff' => [600, true, 'The closing note can be up to 600 characters.'],
        'report_confidential' => [120, false, 'The confidential label can be up to 120 characters.'],
    ];

    /**
     * POST /admin/branding: report branding (admins; the route checks the role and CSRF). Name, two colors, cover
     * style, contact block, sign-off, confidential label, footer note, logo, paper and the "Generated by" line.
     *
     * Untrusted: every field. Text is checked against BRAND_TEXT, colors must be #rrggbb (they are written into the
     * report's CSS), the email must be a valid address and the website a plain host name or http(s) address.
     */
    public function branding(Request $request): Response
    {
        $s = App::settings();
        $v = [];
        foreach (array_keys(self::BRAND_TEXT) as $k) {
            $v[$k] = trim(str_replace("\r\n", "\n", $request->input($k)));
        }
        $v += [
            'brand_color' => strtolower($request->input('brand_color')),
            // A form from before 1.59 (an old tab) has no accent or cover field: keep the saved value.
            'brand_accent' => strtolower($request->input('brand_accent') !== '' ? $request->input('brand_accent') : $s->get('brand_accent')),
            'report_cover' => $request->input('report_cover') !== '' ? $request->input('report_cover') : $s->get('report_cover'),
            'report_paper' => $request->input('report_paper'),
            'report_powered_by' => $request->input('report_powered_by') === '1' ? '1' : '0',
            'brand_logo_has_name' => $request->input('brand_logo_has_name') === '1' ? '1' : '0',
        ];
        $errors = [];
        foreach (self::BRAND_TEXT as $k => [$max, $multi, $message]) {
            $bad = $multi ? '/[\x00-\x09\x0B-\x1F\x7F]/u' : '/[\x00-\x1F\x7F]/u';
            if (!mb_check_encoding($v[$k], 'UTF-8') || mb_strlen($v[$k]) > $max || preg_match($bad, $v[$k])) {
                $errors[] = __($message);
            }
        }
        if ($v['brand_email'] !== '' && filter_var($v['brand_email'], FILTER_VALIDATE_EMAIL) === false) {
            $errors[] = __('The email address does not look right (for example support@msp.example).');
        }
        if ($v['brand_website'] !== '' && !preg_match('#^(https?://)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(/[^\s<>"]*)?$#i', $v['brand_website'])) {
            $errors[] = __('The website should be a web address such as www.msp.example.');
        }
        foreach (['brand_color', 'brand_accent'] as $k) {
            if (!preg_match('/^#[0-9a-f]{6}$/', $v[$k])) {
                $errors[] = __('The color must look like #1f4e79.');
            }
        }
        if (!in_array($v['report_cover'], ['color', 'white'], true)) {
            $errors[] = __('Choose a full-color or a white cover.');
        }
        if (!in_array($v['report_paper'], ['A4', 'Letter'], true)) {
            $errors[] = __('Choose A4 or Letter paper.');
        }
        $logo = null;
        $upload = $request->uploadedFile('brand_logo');
        $uploadError = $request->uploadError('brand_logo');
        if ($upload === null && $uploadError !== UPLOAD_ERR_NO_FILE) {
            $errors[] = in_array($uploadError, [UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE], true)
                ? __('The logo file is larger than the server accepts. Use a file of at most 2 MB.')
                : __('The logo upload did not complete. Please try again.');
        }
        if ($upload !== null) {
            $logo = App::branding()->storeLogo($upload);
            if (is_array($logo)) {
                $errors[] = $logo[0];
            }
        }
        if ($errors !== []) {
            foreach ($errors as $e) {
                Session::flash('danger', $e);
            }
            return Response::redirect('/admin/settings#branding');
        }
        $changed = [];
        foreach ($v as $name => $value) {
            if ($s->get($name) !== $value) {
                $s->set($name, $value);
                // Free text is logged as "changed" only; colors and choices with their value.
                $changed[$name] = isset(self::BRAND_TEXT[$name]) && $name !== 'brand_name' ? 'changed' : $value;
            }
        }
        if (is_string($logo)) {
            $s->set('brand_logo', $logo);
            App::branding()->deleteOthers($logo);
            $changed['brand_logo'] = 'uploaded';
        } elseif ($request->input('remove_logo') === '1' && $s->get('brand_logo') !== '') {
            $s->set('brand_logo', '');
            App::branding()->deleteOthers('');
            $changed['brand_logo'] = 'removed';
        }
        if ($changed !== []) {
            $this->audit($request, 'settings.branding_updated', null, null, ['changed' => $changed]);
        }
        Session::flash('success', __('Report branding saved. It applies to new reports; saved reports keep the branding they were made with.'));
        return Response::redirect('/admin/settings#branding');
    }

    /**
     * GET /admin/branding/preview?kind=executive|technical: a made-up report with the current branding (1.59), so admins
     * can check their branding before real reports use it. Admins only (the route checks the role). Nothing is stored;
     * the sample data is fixed text (ReportPreview) and the document is served with the same strict CSP as real reports.
     */
    public function brandingPreview(Request $request): Response
    {
        $kind = $request->query('kind') === 'technical' ? 'technical' : 'executive';
        $html = App::reportRenderer()->render(\Sentinel\Reports\ReportPreview::snapshot(App::reportBuilder()->brand(), $kind, App::version()));
        return Response::html($html)->header('Content-Security-Policy', self::REPORT_CSP);
    }

    /**
     * Branding values for the settings form.
     *
     * @return array<string,mixed>
     */
    public static function brandingSettings(): array
    {
        $s = App::settings();
        $values = [];
        foreach (array_merge(array_keys(self::BRAND_TEXT), ['brand_color', 'brand_accent', 'report_cover', 'report_paper', 'report_powered_by', 'brand_logo_has_name']) as $k) {
            $values[$k] = $s->get($k);
        }
        return $values + ['logo' => App::branding()->dataUri($s->get('brand_logo')), 'product_name' => $s->get('product_name')];
    }

    /**
     * Period start and end (Y-m-d, UTC) for a choice.
     *
     * @return array{0:string, 1:string}
     */
    public static function period(string $choice, ?DateTimeImmutable $now = null): array
    {
        $now ??= new DateTimeImmutable('now', new DateTimeZone('UTC'));
        return match ($choice) {
            'month' => [$now->modify('first day of last month')->format('Y-m-d'), $now->modify('last day of last month')->format('Y-m-d')],
            '90' => [$now->modify('-89 days')->format('Y-m-d'), $now->format('Y-m-d')],
            default => [$now->modify('-29 days')->format('Y-m-d'), $now->format('Y-m-d')],
        };
    }

    /** A safe download file name: report-12-executive-2026-11-30.html */
    private static function fileName(array $report, string $ext): string
    {
        return 'report-' . (int) $report['id'] . '-' . (in_array($report['kind'], ['executive', 'technical', 'pentest', 'retest'], true) ? $report['kind'] : 'report') . '-'
            . preg_replace('/[^0-9-]/', '', (string) $report['period_end']) . '.' . $ext;
    }

    /** The client from {id}, or 404. */
    private function client(array $params): array
    {
        $client = ctype_digit((string) ($params['id'] ?? '')) ? App::clients()->find((int) $params['id']) : null;
        if ($client === null) {
            throw new HttpException(404);
        }
        return $client;
    }

    /** The report from {id}, or 404. */
    private function report(array $params): array
    {
        $report = ctype_digit((string) ($params['id'] ?? '')) ? App::reports()->find((int) $params['id']) : null;
        if ($report === null) {
            throw new HttpException(404);
        }
        return $report;
    }
}

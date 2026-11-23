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
            'reports' => App::reports()->list($clientId),
            'clients' => App::clients()->all(),
            'clientFilter' => $clientId,
        ]);
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
        return Response::redirect(count($ids) === 1 ? '/reports/' . $ids[0] : '/reports?client=' . (int) $client['id']);
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
        return Response::html((string) $report['html'])->header('Content-Security-Policy', self::REPORT_CSP);
    }

    /** GET /reports/{id}/download: the document as a self-contained HTML file. */
    public function download(Request $request, array $params): Response
    {
        $report = $this->report($params);
        return Response::html((string) $report['html'])
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
        return (new Response(CsvExport::build($snapshot)))
            ->header('Content-Type', 'text/csv; charset=UTF-8')
            ->header('Content-Security-Policy', "default-src 'none'; sandbox")
            ->header('Content-Disposition', 'attachment; filename="' . self::fileName($report, 'csv') . '"');
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

    /** POST /admin/branding: report branding (name, colour, footer, logo, paper, "Generated by" line). */
    public function branding(Request $request): Response
    {
        $s = App::settings();
        $v = [
            'brand_name' => $request->input('brand_name'),
            'brand_color' => strtolower($request->input('brand_color')),
            'brand_footer' => str_replace("\r\n", "\n", $request->input('brand_footer')),
            'report_paper' => $request->input('report_paper'),
            'report_powered_by' => $request->input('report_powered_by') === '1' ? '1' : '0',
        ];
        $errors = [];
        if (!mb_check_encoding($v['brand_name'], 'UTF-8') || mb_strlen($v['brand_name']) > 100 || preg_match('/[\x00-\x1F\x7F]/u', $v['brand_name'])) {
            $errors[] = __('The company name can be up to 100 characters.');
        }
        if (!preg_match('/^#[0-9a-f]{6}$/', $v['brand_color'])) {
            $errors[] = __('The colour must look like #1f4e79.');
        }
        if (!mb_check_encoding($v['brand_footer'], 'UTF-8') || mb_strlen($v['brand_footer']) > 500 || preg_match('/[\x00-\x09\x0B-\x1F\x7F]/u', $v['brand_footer'])) {
            $errors[] = __('The footer can be up to 500 characters.');
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
                $changed[$name] = $name === 'brand_footer' ? 'changed' : $value;
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
     * Branding values for the settings form.
     *
     * @return array<string,mixed>
     */
    public static function brandingSettings(): array
    {
        $s = App::settings();
        $values = [];
        foreach (['brand_name', 'brand_color', 'brand_footer', 'report_paper', 'report_powered_by'] as $k) {
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

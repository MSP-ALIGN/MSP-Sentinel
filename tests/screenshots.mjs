/*
 * Takes screenshots of the main pages for release notes and review.
 *
 * Usage:
 *   php tests/run.php --serve &            # prints the URL and writes serve.json
 *   node tests/screenshots.mjs <path-to-serve.json>
 *
 * Signs in as the demo admin (made-up account created by run.php), sets up 2FA
 * by reading the key from the page and computing the code locally, then visits
 * each page. Only talks to 127.0.0.1. Output: tests/output/screenshots/.
 */
import { readFileSync, mkdirSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { createRequire } from 'node:module';

// CommonJS require finds a globally installed Playwright, which ESM import doesn't.
const { chromium } = createRequire(import.meta.url)('playwright');

const serve = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const base = serve.url;
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(base)) throw new Error('Refusing to screenshot anything but 127.0.0.1');
const out = new URL('./output/screenshots/', import.meta.url).pathname;
mkdirSync(out, { recursive: true });

function base32Decode(s) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/\s|=/g, '')) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
function totp(secret, offset = 0) {
  const step = Math.floor(Date.now() / 1000 / 30) + offset;
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(step));
  const h = createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const o = h[19] & 0xf;
  const v = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(v % 1e6).padStart(6, '0');
}

const browser = await chromium.launch();
const shot = async (page, name) => page.screenshot({ path: `${out}${name}.png`, fullPage: true });

async function signIn(context, username, password, prefix) {
  const page = await context.newPage();
  await page.goto(`${base}/login`);
  if (prefix !== null) await shot(page, `${prefix}01-login`);
  await page.fill('#username', username);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
  await page.waitForURL(/2fa\/setup/);
  await page.waitForSelector('#totp-qr img');
  if (prefix !== null) await shot(page, `${prefix}02-2fa-setup`);
  const secret = (await page.textContent('[data-testid=totp-secret]')).trim();
  await page.fill('#code', totp(secret));
  await page.click('form[action$="/2fa/setup"] button[type=submit]');
  await page.waitForURL(/recovery-codes/);
  if (prefix !== null) await shot(page, `${prefix}03-recovery-codes`);
  return page;
}

const desktop = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2 });
const page = await signIn(desktop, 'admin', 'Admin-Pass-0001!', '');
for (const [path, name] of [['/', '04-dashboard'], ['/users', '05-users'], ['/users/new', '06-user-new'], ['/users/2', '07-user-edit'],
                            ['/admin/audit', '08-audit-log'], ['/admin/settings', '09-settings'], ['/help', '10-help'], ['/profile', '11-profile']]) {
  await page.goto(base + path);
  await shot(page, name);
}

// Clients and the authorised-to-scan register (made-up client, documentation addresses only).
await page.goto(`${base}/clients/new`);
await page.fill('#name', 'Contoso Example Ltd');
await page.fill('#itflow_client_id', '17');
await page.selectOption('#timezone', 'Europe/London');
await page.fill('#scan_window_start', '00:00');
await page.fill('#scan_window_end', '23:59');
await shot(page, '14-client-new');
await page.click('.app-content form button.btn-primary[type=submit]');
await page.waitForURL(/\/clients\/\d+$/);
const clientUrl = page.url();
await page.goto(`${clientUrl}/authorisations/new`);
await page.fill('#approved_by_name', 'Dana Example');
await page.fill('#approved_by_role', 'Managing Director');
await page.fill('#document_ref', 'TICKET-1001');
await page.fill('#scope', '# Office and website\n203.0.113.10\n198.51.100.0/28\ncontoso.example\n*.contoso.example\n10.0.0.0/24');
await page.check('#confirm');
await page.click('.app-content form button.btn-primary[type=submit]');
await shot(page, '15-authorisation-errors');
await page.fill('#scope', '# Office and website\n203.0.113.10\n203.0.113.160\n203.0.113.180\n203.0.113.181\n203.0.113.190\ndiscovery.example\nmail-good.example\nmail-weak.example');
await page.check('#confirm');
await page.click('.app-content form button.btn-primary[type=submit]');
await page.waitForURL(/\/clients\/\d+$/);
await page.click('#discovery form button[type=submit]');
await page.waitForURL(/\/clients\/\d+$/);
await shot(page, '16-client-detail');
await page.locator('#discovery').screenshot({ path: `${out}18-discovery.png` });
// Alerts: point email and the webhook at the harness's fake mail server and receiver (127.0.0.1 only).
await page.goto(`${base}/admin/settings`);
await page.check('#email_enabled');
await page.fill('#smtp_host', '127.0.0.1');
await page.fill('#smtp_port', String(serve.smtp_port));
await page.selectOption('#smtp_security', 'none');
await page.fill('#smtp_from', 'sentinel@msp.example');
await page.fill('#team_addresses', 'alerts@msp.example');
await page.check('#webhook_enabled');
await page.fill('#webhook_url', `${serve.feeds_url}/webhook`);
await page.selectOption('#webhook_format', 'teams');
await page.click('#alerts form[action$="/admin/alerts"] button[type=submit]');
await page.waitForURL(/\/admin\/settings/);
await page.click('#alerts form[action$="/admin/alerts/test"] button');
await page.waitForURL(/\/admin\/settings/);
await page.goto(clientUrl);
// Port scan: queue it, run the worker once (fake nmap from the test harness, no packets sent), then show results.
await page.click('#scans form button.btn-primary[type=submit]');
await page.waitForURL(/\/clients\/\d+/);
const { execFileSync } = createRequire(import.meta.url)('node:child_process');
execFileSync('php', [new URL('../bin/worker.php', import.meta.url).pathname, '--no-schedule'],
  { env: { ...process.env, SENTINEL_CONFIG: `${serve.dir}/config.php`, SENTINEL_TEST_MODE: '1', SENTINEL_ALLOW_ROOT: '1' } });
execFileSync('php', [new URL('../bin/feeds.php', import.meta.url).pathname],
  { env: { ...process.env, SENTINEL_CONFIG: `${serve.dir}/config.php`, SENTINEL_TEST_MODE: '1' } });
await page.goto(clientUrl);
await page.locator('#scans').screenshot({ path: `${out}19-port-scan.png` });
await page.locator('#vulns').screenshot({ path: `${out}21-vulnerabilities.png` });
await page.locator('#exposure').screenshot({ path: `${out}20-certificates-web.png` });
await page.locator('#website').screenshot({ path: `${out}39-website-email.png` });
await page.locator('#findings').screenshot({ path: `${out}22-client-findings.png` });
await page.goto(`${base}/`);
await page.locator('.app-header').screenshot({ path: `${out}26-notification-bell.png` });
await page.goto(`${base}/notifications`);
await shot(page, '27-notifications');
await page.goto(`${base}/admin/settings`);
await page.locator('#alerts').screenshot({ path: `${out}25-alert-settings.png` });
await page.goto(`${base}/findings`);
await shot(page, '23-findings');
await page.click('table a[href*="/findings/"]');
await page.waitForURL(/\/findings\/\d+$/);
// Fix workflow: take the finding, then show the fix card and the list with owners and due dates.
await page.click('#fix form input[value="me"] + button');
await page.waitForURL(/\/findings\/\d+$/);
await shot(page, '24-finding-detail');
await page.locator('#fix').screenshot({ path: `${out}40-fix-card.png` });
await page.goto(`${base}/findings?assignee=me`);
await shot(page, '41-findings-mine');
// Reports: branding (made-up MSP), then both reports for the demo client.
await page.goto(`${base}/admin/settings`);
await page.fill('#brand_name', 'Example MSP Ltd');
await page.fill('#brand_footer', 'Example MSP Ltd · support@msp.example · 555-0100');
await page.click('#branding button[type=submit]');
await page.waitForURL(/\/admin\/settings/);
await page.locator('#branding').screenshot({ path: `${out}28-report-branding.png` });
await page.goto(clientUrl);
await page.click('#reports form[action$="/reports"] button[type=submit]');
await page.waitForURL(/\/reports/);
await shot(page, '29-reports');
await page.goto(clientUrl);
await page.locator('#reports').screenshot({ path: `${out}30-client-reports.png` });
await page.goto(`${base}/reports`);
await page.click('table a[href*="/reports/"]');
await page.waitForURL(/\/reports\/\d+$/);
await shot(page, '31-report-detail');
for (const [kind, name] of [['technical', '33-report-technical'], ['executive', '32-report-executive']]) {
  await page.goto(`${base}/reports`);
  const href = await page.locator(`table tr:has-text("${kind === 'executive' ? 'Executive summary' : 'Technical findings'}") a[href$="/view"]`).first().getAttribute('href');
  await page.goto(new URL(href, base).href);
  await shot(page, name);
  await page.emulateMedia({ media: 'print' });
  await page.pdf({ path: `${out}${name}.pdf`, format: 'A4', printBackground: true });
  await page.emulateMedia({ media: 'screen' });
}
// API: create a demo token (on the throwaway test database), then reload so the one-time token is NOT in the screenshot.
await page.goto(`${base}/admin/api`);
await page.fill('#token-name', 'MSP Align');
await page.check('#all_clients');
await page.check('#can_triage');
await page.fill('#ip_allowlist', '203.0.113.10');
await page.click('form[action$="/admin/api/tokens"] button[type=submit]');
await page.waitForURL(/\/admin\/api/);
await page.goto(`${base}/admin/api`);
await shot(page, '34-api');
// Administration section (its own menu), reached from the user drop-down.
await page.goto(`${base}/admin`);
await shot(page, '37-administration');
await page.goto(`${base}/`);
await page.click('.navbar .dropdown-toggle');
await page.waitForTimeout(200);
await page.screenshot({ path: `${out}38-user-menu.png`, clip: { x: 900, y: 0, width: 380, height: 420 } });
await page.keyboard.press('Escape');
// System page (health, updates, retention) after one worker run, so the heartbeat shows.
await page.goto(`${base}/admin/system`);
await shot(page, '35-system');
// Light theme (per-user choice on the profile), then back to the dark default.
await page.goto(`${base}/profile`);
await page.check('#theme-light');
await page.click('#appearance button[type=submit]');
await page.waitForURL(/\/profile/);
await page.goto(clientUrl);
await shot(page, '36-client-light');
await page.goto(`${base}/profile`);
await page.check('#theme-dark');
await page.click('#appearance button[type=submit]');
await page.waitForURL(/\/profile/);
await page.goto(`${base}/clients`);
await shot(page, '17-clients');
await page.goto(`${base}/`);
await shot(page, '04-dashboard');

const viewer = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2 });
const vpage = await signIn(viewer, 'victor', 'View-Pass-0001!', null);
await vpage.goto(`${base}/users`);
await shot(vpage, '12-viewer-access-denied');

const phone = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
const ppage = await phone.newPage();
await ppage.goto(`${base}/login`);
await shot(ppage, '13-login-phone');

await browser.close();
console.log(`Screenshots written to ${out}`);

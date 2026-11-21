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

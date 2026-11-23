// Test helper: runs the REAL browser script (public/assets/js/release-key.js) in Node's Web Crypto. Never used in
// production. Input is JSON on stdin; output is JSON on stdout.
//   {"op":"create","password":"..."}                                  -> {file, publicKey}
//   {"op":"sign","file":"...","password":"...","text":"..."}           -> {signature, publicKey}
//   {"op":"rotate","file":"...","password":"...","newPassword":"...","at":"..."} -> {file, publicKey, statement, signature}
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
globalThis.window = globalThis; // no document: the script only defines SentinelReleaseKey
const here = path.dirname(fileURLToPath(import.meta.url));
(0, eval)(fs.readFileSync(path.join(here, '../../public/assets/js/release-key.js'), 'utf8'));
const k = globalThis.SentinelReleaseKey;
const req = JSON.parse(fs.readFileSync(0, 'utf8'));
let out;
if (req.op === 'create') {
    out = await k.create(req.password);
    out.fingerprint = await k.fingerprint(out.publicKey);
    out.fileName = await k.fileName(out.publicKey);
} else if (req.op === 'sign') {
    const u = await k.unlock(req.file, req.password);
    out = { signature: await k.sign(u.privateKey, req.text), publicKey: u.publicKey };
} else if (req.op === 'rotate') {
    const u = await k.unlock(req.file, req.password);
    const n = await k.create(req.newPassword);
    const statement = k.rotationStatement(u.publicKey, n.publicKey, req.at);
    out = { file: n.file, publicKey: n.publicKey, statement, signature: await k.sign(u.privateKey, statement) };
}
process.stdout.write(JSON.stringify(out));

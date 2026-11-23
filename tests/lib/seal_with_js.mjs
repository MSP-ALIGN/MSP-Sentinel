// Test helper: seals a password with the REAL browser script (public/assets/js/agent-seal.js), using Node's Web Crypto
// (the same API browsers have). Usage: node seal_with_js.mjs <agent-public-key-b64> <aad>   (password on stdin)
// Prints the sealed box. Never used in production.
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
globalThis.window = globalThis; // the script expects window; there is no document, so it only defines SentinelSeal
const here = path.dirname(fileURLToPath(import.meta.url));
(0, eval)(fs.readFileSync(path.join(here, '../../public/assets/js/agent-seal.js'), 'utf8'));
const password = fs.readFileSync(0, 'utf8');
process.stdout.write(await globalThis.SentinelSeal.seal(process.argv[2], password, process.argv[3]));

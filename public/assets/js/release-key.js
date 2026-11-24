/*
 * MSP Sentinel: the agent release key, made and used in the admin's browser (Administration, System). Loaded as a
 * file (strict CSP, no inline scripts).
 *
 * The private key never leaves the browser except as the password-protected file the admin downloads and keeps:
 * - create: an Ed25519 key pair (Web Crypto); the private key (PKCS#8) is encrypted with a key derived from the
 *   admin's key password (PBKDF2-SHA256, ITERATIONS rounds, random salt) using AES-256-GCM, and downloaded as a file;
 *   only the public key (raw, base64) is sent to Sentinel.
 * - sign: the admin picks the key file and types its password; the browser decrypts it, checks it matches the release
 *   key Sentinel uses, signs the manifest Sentinel shows (its own files, listed with SHA-256), and sends only the
 *   signature.
 * - rotate: the old key file signs a statement naming the new key, so agents accept the new key without anyone
 *   visiting a site.
 * Password and key fields have no name: the browser never submits them. Needs a secure page (HTTPS).
 */
(function () {
    'use strict';

    var ITERATIONS = 600000;
    var enc = new TextEncoder();

    function b64(bytes) {
        var s = '';
        var a = new Uint8Array(bytes);
        for (var i = 0; i < a.length; i++) {
            s += String.fromCharCode(a[i]);
        }
        return btoa(s);
    }

    function unb64(text) {
        var s = atob(text);
        var a = new Uint8Array(s.length);
        for (var i = 0; i < s.length; i++) {
            a[i] = s.charCodeAt(i);
        }
        return a;
    }

    async function wrapKey(password, salt) {
        var base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
        return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: ITERATIONS }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    }

    /** A new key pair. Resolves to {file (JSON text, password-protected), publicKey (base64)}. */
    async function create(password) {
        var pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
        var pub = b64(await crypto.subtle.exportKey('raw', pair.publicKey));
        var pk8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
        var salt = crypto.getRandomValues(new Uint8Array(16));
        var iv = crypto.getRandomValues(new Uint8Array(12));
        var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, await wrapKey(password, salt), pk8);
        var file = JSON.stringify({ v: 1, type: 'msp-sentinel-release-key', public: pub, kdf: 'PBKDF2-SHA256', iterations: ITERATIONS,
            salt: b64(salt), iv: b64(iv), ct: b64(ct), created: new Date().toISOString() }, null, 2);
        return { file: file, publicKey: pub };
    }

    /** Open a key file with its password. Resolves to {privateKey (CryptoKey), publicKey (base64)}; rejects on a wrong password. */
    async function unlock(fileText, password) {
        var f = JSON.parse(fileText);
        if (!f || f.v !== 1 || f.type !== 'msp-sentinel-release-key') {
            throw new Error('not a release key file');
        }
        var pk8 = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(f.iv) }, await wrapKey(password, unb64(f.salt)), unb64(f.ct));
        var key = await crypto.subtle.importKey('pkcs8', pk8, { name: 'Ed25519' }, false, ['sign']);
        // The file's public key must belong to this private key.
        var probe = enc.encode('msp-sentinel-key-check');
        var pub = await crypto.subtle.importKey('raw', unb64(f.public), { name: 'Ed25519' }, false, ['verify']);
        if (!(await crypto.subtle.verify({ name: 'Ed25519' }, pub, await crypto.subtle.sign({ name: 'Ed25519' }, key, probe), probe))) {
            throw new Error('damaged key file');
        }
        return { privateKey: key, publicKey: f.public };
    }

    async function sign(privateKey, text) {
        return b64(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, enc.encode(text)));
    }

    /** The statement agents need to accept a new key: signed with the old key. Keys in a fixed order (canonical). */
    function rotationStatement(oldKey, newKey, at) {
        return JSON.stringify({ at: at, new_key: newKey, old_key: oldKey, type: 'release_key_rotation', v: 1 });
    }

    /** A key's fingerprint as Sentinel shows it (first 128 bits of SHA-256 of the raw key, in groups of four). */
    async function fingerprint(publicKey) {
        var hex = Array.prototype.map.call(new Uint8Array(await crypto.subtle.digest('SHA-256', unb64(publicKey))), function (b) {
            return ('0' + b.toString(16)).slice(-2);
        }).join('').slice(0, 32).toUpperCase();
        return hex.match(/.{4}/g).join(':');
    }

    /** The key file's name: with the start of its fingerprint, so files of different keys can't be mixed up. */
    async function fileName(publicKey) {
        return 'sentinel-release-key-' + (await fingerprint(publicKey)).slice(0, 9).replace(':', '-') + '.json';
    }

    window.SentinelReleaseKey = { create: create, unlock: unlock, sign: sign, rotationStatement: rotationStatement, fingerprint: fingerprint, fileName: fileName }; // tests run these in Node

    if (typeof document === 'undefined') {
        return;
    }

    function download(name, text) {
        var a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
        a.download = name;
        document.body.appendChild(a);
        a.click();
        setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    }

    function readFile(input) {
        return new Promise(function (resolve, reject) {
            var f = input && input.files && input.files[0];
            if (!f) {
                reject(new Error('choose the key file'));
                return;
            }
            var r = new FileReader();
            r.onload = function () { resolve(String(r.result)); };
            r.onerror = function () { reject(new Error('the key file could not be read')); };
            r.readAsText(f);
        });
    }

    var forms = document.querySelectorAll('form[data-release-key]');
    for (var i = 0; i < forms.length; i++) {
        (function (form) {
            var note = form.querySelector('[data-key-note]');
            var say = function (text) {
                if (note) {
                    note.textContent = text;
                    note.classList.remove('d-none');
                }
            };
            var ok = window.isSecureContext && window.crypto && window.crypto.subtle;
            if (!ok) {
                say(form.getAttribute('data-insecure-text') || 'Open Sentinel over HTTPS to use the release key.');
                var b = form.querySelector('button[type=submit]');
                if (b) {
                    b.disabled = true;
                }
                return;
            }
            var mode = form.getAttribute('data-release-key');
            var busy = false;
            form.addEventListener('submit', function (event) {
                if (form.getAttribute('data-ready') === '1') {
                    return;
                }
                event.preventDefault();
                if (busy) {
                    return;
                }
                var field = function (n) { var el = form.querySelector('[data-key-field=' + n + ']'); return el ? el.value : ''; };
                var set = function (n, v) { form.querySelector('input[name=' + n + ']').value = v; };
                var done = function () { form.setAttribute('data-ready', '1'); form.submit(); };
                var fail = function (e) { busy = false; say((form.getAttribute('data-failed-text') || 'That did not work: ') + (e && e.message ? e.message : '')); };
                busy = true;
                if (mode === 'create' || mode === 'replace') {
                    if (field('new-password').length < 12 || field('new-password') !== field('new-password2')) {
                        fail(new Error(form.getAttribute('data-password-text') || 'use a key password of at least 12 characters, typed twice the same'));
                        return;
                    }
                    create(field('new-password')).then(function (k) {
                        return fileName(k.publicKey).then(function (name) {
                            download(name, k.file);
                            set('public_key', k.publicKey);
                            done();
                        });
                    }).catch(fail);
                } else if (mode === 'sign') {
                    // Sign only what the admin confirmed (1.35): the SHA-256 of the exact manifest text about to be
                    // signed must equal the hash they pasted from the release notes or computed on their own computer
                    // (php bin/release-sign.php hash --ref vX.Y.Z).
                    var manifest = form.querySelector('input[name=manifest]').value;
                    var expected = field('expected-hash').trim().toLowerCase();
                    crypto.subtle.digest('SHA-256', new TextEncoder().encode(manifest)).then(function (d) {
                        var actual = Array.prototype.map.call(new Uint8Array(d), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
                        if (!/^[0-9a-f]{64}$/.test(expected) || expected !== actual) {
                            throw new Error(form.getAttribute('data-hash-text') || 'the files on this server do not match the release hash you entered: do not sign');
                        }
                        set('expected_hash', expected);
                        return readFile(form.querySelector('[data-key-field=file]'));
                    }).then(function (text) {
                        return unlock(text, field('password'));
                    }).then(function (k) {
                        if (k.publicKey !== form.getAttribute('data-public-key')) {
                            throw new Error(form.getAttribute('data-wrong-key-text') || 'this is not the release key Sentinel uses');
                        }
                        return sign(k.privateKey, manifest);
                    }).then(function (sig) {
                        set('signature', sig);
                        done();
                    }).catch(fail);
                } else if (mode === 'rotate') {
                    if (field('new-password').length < 12 || field('new-password') !== field('new-password2')) {
                        fail(new Error(form.getAttribute('data-password-text') || 'use a key password of at least 12 characters, typed twice the same'));
                        return;
                    }
                    var old;
                    readFile(form.querySelector('[data-key-field=file]')).then(function (text) {
                        return unlock(text, field('password'));
                    }).then(function (k) {
                        if (k.publicKey !== form.getAttribute('data-public-key')) {
                            throw new Error(form.getAttribute('data-wrong-key-text') || 'this is not the release key Sentinel uses');
                        }
                        old = k;
                        return create(field('new-password'));
                    }).then(function (n) {
                        var statement = rotationStatement(old.publicKey, n.publicKey, new Date().toISOString().slice(0, 19) + 'Z');
                        return Promise.all([sign(old.privateKey, statement), fileName(n.publicKey)]).then(function (r) {
                            var sig = r[0];
                            download(r[1], n.file);
                            set('public_key', n.publicKey);
                            set('statement', statement);
                            set('statement_signature', sig);
                            done();
                        });
                    }).catch(fail);
                }
            });
        })(forms[i]);
    }
})();

/*
 * MSP Sentinel: seals a site's directory password in the browser, to the site's agent (forms with
 * data-agent-seal). Loaded as a file (strict CSP, no inline scripts).
 *
 * The password field has no name, so the browser never sends it. Left empty, the form saves the other settings only.
 * Otherwise, on submit this script encrypts it to the agent's
 * public key (data-agent-key, base64 SPKI P-256) and puts only the sealed box in the hidden "sealed" field:
 *   ECDH (a one-off P-256 key made here) -> HKDF-SHA256 (salt: that one-off public key, info: INFO) -> AES-256-GCM
 *   with the binding data-aad-prefix + the user name typed here as additional data.
 * Only that agent's private key (on the appliance) can open it; Sentinel relays it without being able to read it.
 * Must match src/AgentClient/AgentKey.php (INFO, the box format and the binding).
 *
 * Web Crypto needs a secure page (HTTPS, or localhost): elsewhere the form says so and sends nothing.
 */
(function () {
    'use strict';

    var INFO = 'msp-sentinel-sealed-v1';

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

    /** Seal plaintext to a base64 SPKI P-256 public key, bound to aad. Resolves to the box as a JSON string. */
    async function seal(publicKeyB64, plaintext, aad) {
        var subtle = window.crypto.subtle;
        var enc = new TextEncoder();
        var agentKey = await subtle.importKey('spki', unb64(publicKeyB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
        var mine = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
        var shared = await subtle.deriveBits({ name: 'ECDH', public: agentKey }, mine.privateKey, 256);
        var epk = new Uint8Array(await subtle.exportKey('spki', mine.publicKey));
        var hkdf = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
        var key = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: epk, info: enc.encode(INFO) }, hkdf, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
        var iv = window.crypto.getRandomValues(new Uint8Array(12));
        var ct = await subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode(aad) }, key, enc.encode(plaintext));
        return JSON.stringify({ v: 1, epk: b64(epk), iv: b64(iv), ct: b64(ct) });
    }

    window.SentinelSeal = { seal: seal }; // for the test suite (Node runs this same function)

    if (typeof document === 'undefined') {
        return;
    }
    var forms = document.querySelectorAll('form[data-agent-seal]');
    for (var i = 0; i < forms.length; i++) {
        (function (form) {
            var note = form.querySelector('[data-seal-note]');
            var say = function (text) {
                if (note) {
                    note.textContent = text;
                    note.classList.remove('d-none');
                }
            };
            if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
                say(form.getAttribute('data-insecure-text') || 'Open Sentinel over HTTPS to set the password.');
                var button = form.querySelector('button[type=submit]');
                if (button) {
                    button.disabled = true;
                }
                return;
            }
            var busy = false;
            form.addEventListener('submit', function (event) {
                if (form.getAttribute('data-sealed-ready') === '1') {
                    return; // second pass: the sealed box is in place, send it
                }
                event.preventDefault();
                if (busy) {
                    return;
                }
                var password = form.querySelector('input[data-seal-password]');
                var user = form.querySelector('input[name=username]');
                var ran = form.querySelector('input[name=seal_js]');
                if (ran) {
                    ran.value = '1'; // tells the server this script ran (an empty password then means "keep the current one")
                }
                if (!password || password.value === '') {
                    form.setAttribute('data-sealed-ready', '1'); // no new password: save the other settings only
                    form.submit();
                    return;
                }
                if (!user || user.value.trim() === '') {
                    say(form.getAttribute('data-missing-text') || 'Enter the user name and the password.');
                    return;
                }
                if ((form.getAttribute('data-agent-key') || '') === '') {
                    say(form.getAttribute('data-nokey-text') || 'This agent cannot receive passwords yet.');
                    return;
                }
                busy = true;
                user.value = user.value.trim(); // send exactly the name the box is bound to
                seal(form.getAttribute('data-agent-key') || '', password.value, (form.getAttribute('data-aad-prefix') || '') + user.value)
                    .then(function (box) {
                        form.querySelector('input[name=sealed]').value = box;
                        password.value = ''; // gone from the page before anything is sent
                        form.setAttribute('data-sealed-ready', '1');
                        form.submit();
                    })
                    .catch(function () {
                        busy = false;
                        say(form.getAttribute('data-failed-text') || 'The password could not be encrypted. Nothing was sent.');
                    });
            });
        })(forms[i]);
    }
})();

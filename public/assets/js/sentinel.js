/*
 * MSP Sentinel front-end helpers. Loaded as a file (no inline scripts, strict CSP).
 *
 * - Renders the TOTP enrolment QR code locally from a data attribute, so the
 *   secret never leaves the browser for a third-party QR service.
 * - Asks for confirmation before submitting forms marked with data-confirm.
 * - Refreshes dashboard panels (elements with data-refresh-url) every 60 seconds
 *   while the tab is visible. Only same-origin fragments marked with the
 *   X-Sentinel-Fragment header are used (server-rendered, already escaped);
 *   anything else (an expired session's sign-in page, an error) stops the refresh.
 */
(function () {
    'use strict';

    var qr = document.getElementById('totp-qr');
    if (qr && typeof window.qrcode === 'function') {
        var code = window.qrcode(0, 'M');
        code.addData(qr.getAttribute('data-otpauth') || '');
        code.make();
        var img = document.createElement('img');
        img.src = code.createDataURL(5, 2);
        img.alt = '';
        qr.appendChild(img);
    }

    document.querySelectorAll('[data-refresh-url]').forEach(function (box) {
        var url = box.getAttribute('data-refresh-url');
        if (!url || url.charAt(0) !== '/' || url.charAt(1) === '/') {
            return; // same-origin paths only
        }
        var timer = null;
        var stop = function () { if (timer) { window.clearInterval(timer); timer = null; } };
        var refresh = function () {
            if (document.visibilityState !== 'visible') {
                return;
            }
            window.fetch(url, { credentials: 'same-origin', redirect: 'error', headers: { 'Accept': 'text/html' } })
                .then(function (res) {
                    if (!res.ok || res.headers.get('X-Sentinel-Fragment') !== '1') {
                        throw new Error('not a fragment');
                    }
                    return res.text();
                })
                .then(function (html) { box.innerHTML = html; })
                .catch(stop);
        };
        timer = window.setInterval(refresh, 60000);
        document.addEventListener('visibilitychange', function () {
            if (timer && document.visibilityState === 'visible') { refresh(); }
        });
    });

    document.addEventListener('submit', function (event) {
        var form = event.target;
        var message = form && form.getAttribute ? form.getAttribute('data-confirm') : null;
        if (message && !window.confirm(message)) {
            event.preventDefault();
        }
    }, true);
})();

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

    // Auto-refresh. Skips while the user is working inside a panel (focus or text selection),
    // can be paused with the "Pause updates" button, never overlaps requests, retries on network
    // or server errors with a growing gap, and stops after 30 minutes without input (so an
    // unattended screen is not kept looking alive; the server also ignores these requests
    // for the idle sign-out).
    var boxes = Array.prototype.slice.call(document.querySelectorAll('[data-refresh-url]'));
    var paused = false;
    var lastInput = Date.now();
    ['keydown', 'pointerdown', 'wheel', 'touchstart'].forEach(function (type) {
        document.addEventListener(type, function () { lastInput = Date.now(); }, { passive: true, capture: true });
    });
    document.querySelectorAll('[data-refresh-toggle]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            paused = !paused;
            document.querySelectorAll('[data-refresh-toggle]').forEach(function (b) {
                b.setAttribute('aria-pressed', paused ? 'true' : 'false');
                b.textContent = paused ? (b.getAttribute('data-label-resume') || 'Resume updates') : (b.getAttribute('data-label-pause') || 'Pause updates');
            });
        });
    });
    boxes.forEach(function (box) {
        var url = box.getAttribute('data-refresh-url') || '';
        var target;
        try { target = new URL(url, window.location.href); } catch (e) { return; }
        if (target.origin !== window.location.origin) {
            return; // same-origin only
        }
        var inFlight = false;
        var stopped = false;
        var failures = 0;
        var nextAt = 0;
        var busy = function () {
            var active = document.activeElement;
            var sel = window.getSelection ? window.getSelection() : null;
            return (active && active !== document.body && box.contains(active)) || (sel && !sel.isCollapsed && box.contains(sel.anchorNode));
        };
        var refresh = function (force) {
            if (stopped || inFlight || paused || document.visibilityState !== 'visible' || busy()) {
                return;
            }
            if (Date.now() - lastInput > 30 * 60 * 1000) {
                stopped = true; // idle: stop until the page is used and reloaded
                return;
            }
            if (!force && Date.now() < nextAt) {
                return;
            }
            inFlight = true;
            window.fetch(target.href, { credentials: 'same-origin', redirect: 'error', headers: { 'Accept': 'text/html' } })
                .then(function (res) {
                    if (res.status >= 500) {
                        throw new Error('retry');
                    }
                    if (!res.ok || res.headers.get('X-Sentinel-Fragment') !== '1') {
                        stopped = true; // signed out or not allowed: never insert anything else
                        throw new Error('stop');
                    }
                    return res.text();
                })
                .then(function (html) {
                    if (!busy() && !paused) {
                        box.innerHTML = html;
                        box.setAttribute('data-refreshed', '1');
                    }
                    failures = 0;
                    nextAt = Date.now() + 55000;
                })
                .catch(function (err) {
                    if (stopped || err.message === 'stop') {
                        stopped = true;
                        return;
                    }
                    failures++;
                    nextAt = Date.now() + Math.min(15 * 60 * 1000, 60000 * Math.pow(2, failures)); // network or server trouble: back off
                })
                .then(function () { inFlight = false; });
        };
        window.setInterval(function () { refresh(false); }, 60000);
        document.addEventListener('visibilitychange', function () {
            if (document.visibilityState === 'visible') { refresh(false); }
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

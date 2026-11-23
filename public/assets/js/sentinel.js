/*
 * MSP Sentinel front-end helpers. Loaded as a file (no inline scripts, strict CSP).
 *
 * - Renders the TOTP enrolment QR code locally from a data attribute, so the
 *   secret never leaves the browser for a third-party QR service.
 * - Asks for confirmation before submitting forms marked with data-confirm.
 * - Copy buttons (data-copy="element id"): copy that element's text (install commands, enrolment codes).
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

    // Tabs whose panes are addressed by the page's #hash (Settings): open the tab named in the address, and keep the
    // address in step when another tab is chosen, so a redirect after saving ("#alerts") lands on the right tab.
    document.querySelectorAll('[data-hash-tabs]').forEach(function (list) {
        var show = function (hash) {
            var button = hash && /^#[a-z0-9-]+$/.test(hash) ? list.querySelector('[data-bs-target="' + hash + '"]') : null;
            if (button && window.bootstrap) {
                window.bootstrap.Tab.getOrCreateInstance(button).show();
                // The browser jumps to the element named in the address; keep the tabs and the title in view instead.
                window.requestAnimationFrame(function () { window.scrollTo(0, 0); });
            }
        };
        show(window.location.hash);
        list.addEventListener('shown.bs.tab', function (event) {
            var target = event.target.getAttribute('data-bs-target');
            if (target && window.history && window.history.replaceState) {
                window.history.replaceState(null, '', target);
            }
        });
        window.addEventListener('hashchange', function () { show(window.location.hash); });
    });

    document.addEventListener('click', function (event) {
        var button = event.target && event.target.closest ? event.target.closest('[data-copy]') : null;
        var source = button ? document.getElementById(button.getAttribute('data-copy')) : null;
        if (!source || !navigator.clipboard) {
            return; // no clipboard (plain HTTP): the text can still be selected by hand
        }
        navigator.clipboard.writeText(source.textContent.trim()).then(function () {
            var label = button.getAttribute('data-copied');
            if (label) {
                button.setAttribute('title', label);
                button.classList.add('btn-success');
                setTimeout(function () { button.classList.remove('btn-success'); }, 1500);
            }
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

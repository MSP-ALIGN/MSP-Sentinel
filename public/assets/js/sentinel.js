/*
 * MSP Sentinel front-end helpers. Loaded as a file (no inline scripts, strict CSP).
 *
 * - Renders the TOTP enrolment QR code locally from a data attribute, so the
 *   secret never leaves the browser for a third-party QR service.
 * - Asks for confirmation before submitting forms marked with data-confirm.
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

    document.addEventListener('submit', function (event) {
        var form = event.target;
        var message = form && form.getAttribute ? form.getAttribute('data-confirm') : null;
        if (message && !window.confirm(message)) {
            event.preventDefault();
        }
    }, true);
})();

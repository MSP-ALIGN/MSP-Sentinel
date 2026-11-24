<?php

declare(strict_types=1);

/**
 * Unit tests for the mail message builder, address checks and webhook formats/URL checks.
 */

use Sentinel\Alerts\SmtpMailer;
use Sentinel\Alerts\WebhookSender;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'email messages cannot be used to inject headers' => function (TestContext $ctx): void {
        $msg = SmtpMailer::buildMessage('sentinel@msp.example', ['a@msp.example'], "Hello\r\nBcc: victim@evil.example", "Line 1\n.\nLine 3");
        [$head, $body] = explode("\r\n\r\n", $msg, 2);
        Assert::notContains('Bcc:', $head, 'subject line breaks removed and the subject is encoded');
        Assert::contains('Subject: =?UTF-8?B?', $head);
        Assert::same("Line 1\n.\nLine 3", base64_decode(str_replace("\r\n", '', $body)), 'body survives intact (base64)');
        foreach (["a@b.example\r\nBcc: x@y.example", 'a@b.example, c@d.example', '<a@b.example>', 'not-an-address', str_repeat('a', 250) . '@b.example'] as $bad) {
            Assert::true(!SmtpMailer::validAddress($bad), 'rejected: ' . json_encode($bad));
        }
        Assert::true(SmtpMailer::validAddress('alerts@msp.example'), 'plain address accepted');
        $long = SmtpMailer::buildMessage('s@msp.example', ['a@msp.example'], str_repeat('Überwachung ', 30), 'b');
        foreach (explode("\r\n", explode("\r\n\r\n", $long, 2)[0]) as $line) {
            Assert::true(strlen($line) <= 78, 'header lines folded: ' . strlen($line));
        }
    },
    'plain SMTP is refused to anything but a local relay' => function (TestContext $ctx): void {
        $m = new SmtpMailer('mail.example.com', 25, 'none', 'u', 'secret-pw', 'sentinel@msp.example');
        try {
            $m->send(['a@msp.example'], 's', 'b');
            Assert::true(false, 'should refuse');
        } catch (RuntimeException $ex) {
            Assert::contains('only allowed to a relay on this server', $ex->getMessage());
            Assert::notContains('secret-pw', $ex->getMessage());
        }
    },
    'webhook URL checks block plain http and private networks' => function (TestContext $ctx): void {
        $prod = new WebhookSender(false);
        foreach (['http://hooks.example/x', 'https://10.1.2.3/hook', 'https://127.0.0.1/hook', 'https://[::1]/hook', 'https://169.254.169.254/latest',
                  'https://203.0.113.5/hook', 'https://user:pw@hooks.example/x', 'ftp://hooks.example/x', 'http://127.0.0.1:8080/hook'] as $bad) {
            Assert::true(is_string($prod->check($bad)), 'refused in production: ' . $bad);
        }
        putenv('SENTINEL_TEST_MODE');
        Assert::true(!\Sentinel\Core\App::webhookTestMode(), 'the config flag alone does not enable webhook test mode');
        putenv('SENTINEL_TEST_MODE=1');
        Assert::true(\Sentinel\Core\App::webhookTestMode(), 'harness: config flag plus environment variable');
        $test = new WebhookSender(true);
        Assert::true(is_array($test->check('http://127.0.0.1:8080/hook')), 'local http allowed only in test mode');
    },
    'webhook formats carry only the summary, escaped for each tool' => function (TestContext $ctx): void {
        $alert = ['title' => 'Fail: RDP <open> & exposed', 'text' => 'Client X: 203.0.113.5:3389', 'severity' => 'fail', 'client' => 'Client X', 'items' => ['a', 'b'], 'link' => 'https://sentinel.example/findings/1'];
        $teams = WebhookSender::format('teams', $alert);
        Assert::same('application/vnd.microsoft.card.adaptive', $teams['attachments'][0]['contentType']);
        Assert::same('Attention', $teams['attachments'][0]['content']['body'][0]['color']);
        $slack = WebhookSender::format('slack', $alert);
        Assert::contains('RDP &lt;open&gt; &amp; exposed', $slack['blocks'][0]['text']['text'], 'Slack control characters escaped');
        $json = WebhookSender::format('json', $alert);
        Assert::same(['source', 'severity', 'client', 'title', 'text', 'items', 'link', 'sent_at'], array_keys($json));
    },
];

<?php
declare(strict_types=1);

header('Content-Type: text/plain; charset=UTF-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo 'Method not allowed';
    exit;
}

$name = trim((string) ($_POST['name'] ?? ''));
$email = trim((string) ($_POST['email'] ?? ''));
$message = trim((string) ($_POST['message'] ?? ''));

if ($name === '' || $email === '' || $message === '') {
    http_response_code(400);
    echo 'Please fill in all required fields.';
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo 'Please provide a valid email address.';
    exit;
}

$env = loadEnv(__DIR__ . '/.env');
$smtpConfig = [
    'host' => $env['SMTP_HOST'] ?? '',
    'port' => (int) ($env['SMTP_PORT'] ?? 587),
    'user' => $env['SMTP_USER'] ?? '',
    'pass' => $env['SMTP_PASS'] ?? '',
    'secure' => $env['SMTP_SECURE'] ?? 'tls',
    'from' => $env['SMTP_FROM'] ?? 'BridgeBox Website <no-reply@zeetechfoundation.org>',
];
$recipient = $env['CONTACT_RECIPIENT'] ?? 'info@zeetechfoundation.org';
$subject = 'BridgeBox Website Inquiry from ' . $name;
$body = "Name: $name\nEmail: $email\n\nMessage:\n$message\n";
$replyTo = $email;

$sent = false;
if ($smtpConfig['host'] !== '' && $smtpConfig['user'] !== '' && $smtpConfig['pass'] !== '') {
    $sent = sendEmailViaSmtp($smtpConfig, $smtpConfig['from'], $recipient, $subject, $body, $replyTo);
}

if (!$sent) {
    $headers = [
        'From' => $smtpConfig['from'],
        'Reply-To' => $replyTo,
        'Content-Type' => 'text/plain; charset=UTF-8',
    ];
    $headerLines = '';
    foreach ($headers as $key => $value) {
        $headerLines .= sprintf('%s: %s\r\n', $key, $value);
    }
    $sent = mail($recipient, $subject, $body, $headerLines);
}

if ($sent) {
    echo 'Thank you for reaching out. We will follow up soon.';
    exit;
}

http_response_code(500);
error_log('Contact form failed to send: ' . $body);
echo 'We could not deliver your message right now. Please try again later.';

function loadEnv(string $path): array
{
    if (!is_readable($path)) {
        return [];
    }

    $env = [];
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') {
            continue;
        }
        $parts = explode('=', $line, 2);
        if (!isset($parts[1])) {
            continue;
        }
        $env[trim($parts[0])] = trim($parts[1], " \t\n\r\0\x0B\"'");
    }
    return $env;
}

function sendEmailViaSmtp(array $config, string $from, string $recipient, string $subject, string $body, string $replyTo): bool
{
    $host = $config['host'] ?? '';
    $port = $config['port'] ?? 587;
    $user = $config['user'] ?? '';
    $pass = $config['pass'] ?? '';
    $secure = strtolower($config['secure'] ?? 'tls');

    if ($host === '' || $user === '' || $pass === '' || $recipient === '') {
        return false;
    }

    $remote = ($secure === 'ssl' ? 'ssl://' . $host : $host);
    $context = stream_context_create([
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false,
        ],
    ]);

    $socket = @stream_socket_client(sprintf('%s:%d', $remote, $port), $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
    if ($socket === false) {
        error_log(sprintf('SMTP connect failed: %s', $errstr));
        return false;
    }

    stream_set_timeout($socket, 30);

    if (!smtpExpect($socket, 220)) {
        fclose($socket);
        return false;
    }

    smtpSend($socket, 'EHLO localhost');
    if (!smtpExpect($socket, 250)) {
        fclose($socket);
        return false;
    }

    if ($secure === 'tls') {
        smtpSend($socket, 'STARTTLS');
        if (!smtpExpect($socket, 220)) {
            fclose($socket);
            return false;
        }
        stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        smtpSend($socket, 'EHLO localhost');
        if (!smtpExpect($socket, 250)) {
            fclose($socket);
            return false;
        }
    }

    smtpSend($socket, 'AUTH LOGIN');
    if (!smtpExpect($socket, 334)) {
        fclose($socket);
        return false;
    }

    smtpSend($socket, base64_encode($user));
    if (!smtpExpect($socket, 334)) {
        fclose($socket);
        return false;
    }

    smtpSend($socket, base64_encode($pass));
    if (!smtpExpect($socket, 235)) {
        fclose($socket);
        return false;
    }

    $fromEmail = extractEmailAddress($from);
    smtpSend($socket, sprintf('MAIL FROM:<%s>', $fromEmail));
    if (!smtpExpect($socket, 250)) {
        fclose($socket);
        return false;
    }

    smtpSend($socket, sprintf('RCPT TO:<%s>', $recipient));
    if (!smtpExpect($socket, 250, 251)) {
        fclose($socket);
        return false;
    }

    smtpSend($socket, 'DATA');
    if (!smtpExpect($socket, 354)) {
        fclose($socket);
        return false;
    }

    $message = buildSmtpMessage($from, $replyTo, $subject, $body);
    smtpSendRaw($socket, $message);
    if (!smtpExpect($socket, 250)) {
        fclose($socket);
        return false;
    }

    smtpSend($socket, 'QUIT');
    smtpExpect($socket, 221);
    fclose($socket);
    return true;
}

function smtpSend($socket, string $command): void
{
    fwrite($socket, $command . "\r\n");
}

function smtpSendRaw($socket, string $payload): void
{
    fwrite($socket, $payload);
}

function smtpReadResponse($socket): ?string
{
    $response = '';
    while (($line = fgets($socket, 515)) !== false) {
        $response .= $line;
        if (!isset($line[3]) || $line[3] !== '-') {
            break;
        }
    }
    return $response === '' ? null : $response;
}

function smtpExpect($socket, int ...$codes): bool
{
    $response = smtpReadResponse($socket);
    if ($response === null) {
        return false;
    }
    $code = (int) substr($response, 0, 3);
    foreach ($codes as $expected) {
        if ($code === $expected) {
            return true;
        }
    }
    return false;
}

function buildSmtpMessage(string $from, string $replyTo, string $subject, string $body): string
{
    $headers = [
        sprintf('From: %s', $from),
        sprintf('Reply-To: %s', $replyTo),
        sprintf('Subject: %s', $subject),
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: 8bit',
    ];

    $normalizedBody = str_replace(["\r\n", "\r"], "\n", $body);
    $lines = explode("\n", $normalizedBody);
    foreach ($lines as &$line) {
        if (isset($line[0]) && $line[0] === '.') {
            $line = '.' . $line;
        }
    }
    $payload = implode("\r\n", $lines);

    return implode("\r\n", $headers) . "\r\n\r\n" . $payload . "\r\n.\r\n";
}

function extractEmailAddress(string $value): string
{
    if (preg_match('/<([^>]+)>/', $value, $matches)) {
        return $matches[1];
    }
    return $value;
}

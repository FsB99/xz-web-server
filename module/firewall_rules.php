<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

// credited to : https://github.com/coreruleset/coreruleset
// Since CRS used regex and SecLang, this will be the re-implementasion for lightweight and performance wise for PHP

// $struct_scorebase = [
//   5 => 'critical',
//   4 => 'error',
//   3 => 'warning',
//   2 => 'notice',
// ];

// $struct_scan_where = [
//   'REQUEST_METHOD' => 'GET/POST/etc',
//   'ARGS' => 'request parameters',
//   'ARGS_NAMES' => 'parameter names',
//   'REQUEST_HEADERS' => 'headers',
//   'REQUEST_FILENAME' => 'URL path',
//   'REQUEST_COOKIES' => 'cookie',
// ];

// https://capec.mitre.org/data/definitions/272.html

$r911 = include './module/firewall/911.php';
$r913 = include './module/firewall/913.php';
$r920 = include './module/firewall/920.php';
$crs_rules_raw = array_merge($r911, $r913, $r920);

$GLOBALS['crs_rules'] = $crs_rules_raw;
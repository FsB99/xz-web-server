<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

// credited to : https://github.com/coreruleset/coreruleset
// Since CRS used regex and SecLang, this will be the re-implementasion for lightweight and performance wise for PHP
// https://capec.mitre.org/data/definitions/272.html

$r911 = include './module/firewall/911.php';
$r913 = include './module/firewall/913.php';
$r920 = include './module/firewall/920.php';
$r921 = include './module/firewall/921.php';
$r930 = include './module/firewall/930.php';
$r931 = include './module/firewall/931.php';
$r933 = include './module/firewall/933.php';
$r934 = include './module/firewall/934.php';
$r941 = include './module/firewall/941.php';
$r942 = include './module/firewall/942.php';
$r943 = include './module/firewall/943.php';

$GLOBALS['crs_rules'] = \array_merge($r911, $r913, $r920, $r921, $r930, $r931, $r933, $r934, $r941, $r942, $r943);
unset($r911, $r913, $r920, $r921, $r930, $r931, $r933, $r934, $r941);
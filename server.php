<?php
// XZ Web Server by Fsb
declare(strict_types=1);
set_time_limit(0);
error_reporting(E_ALL);

$GLOBALS['server_cnf'] = [
  'host' => '0.0.0.0',
  'port' => 8080,
  'max_header_size' => 8192,
  'max_body_size' => 1048576 * 2, // 1Mb base
  'max_uri_length' => 2048,
  'idle_second' => 10,
  'os' => (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' ? 'win' : 'unix'),
  'ext_ev' => extension_loaded('ev'),
  'ext_pcntl' => function_exists('pcntl_fork'),
  'module_list' => ['firewall'],
  'module_enabled' => ['firewall'],
];

$GLOBALS['routes'] = [
  ['path' => '/', 'm' => 'get', 'fn' => 'gui_homepage', 'mw' => []],
  ['path' => '/test', 'm' => 'get', 'fn' => 'gui_testpage', 'mw' => []],
];

include './module/webf.php';
include './module/http.php';

static $module_enabled = null, $module_list = null;
if (\is_null($module_enabled)) {
  global $server_cnf;
  $module_enabled = $server_cnf['module_enabled'] ?? [];
  $module_list = $server_cnf['module_list'] ?? [];
}

foreach ($module_enabled as &$me) {
  if (\in_array($me, $module_list)) {
    include './module/'.$me.'.php';
    echo 'Load module: '.$me.PHP_EOL;
  }
}
echo PHP_EOL;

if (\in_array(PHP_SAPI, ['cli', 'micro'])) server_start($server_cnf['host'], $server_cnf['port'], $server_cnf['workers']);
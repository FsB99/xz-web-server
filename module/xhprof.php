<?php
// XZ Web Server by Fsb
if (!\defined('ABSPATH')) exit();

function profiler_start(): void {
  if (\function_exists('xhprof_enable')) {
    $flags = 0;
    if (\defined('XHPROF_FLAGS_CPU')) $flags |= XHPROF_FLAGS_CPU;
    if (\defined('XHPROF_FLAGS_MEMORY')) $flags |= XHPROF_FLAGS_MEMORY;
    xhprof_enable($flags);
  }
}

function profiler_stop(string $tag = 'app'): string|bool|null {
  $rt = false;
  static $lib_path = null;
  if (null === $lib_path) {
    global $server_cnf;
    $lib_path = $server_cnf['xhprof_lib_path'] ?? null;
  }

  if (!\function_exists('xhprof_disable')) return false;

  $data = xhprof_disable();

  if (\function_exists('xhprof_disable') && \class_exists('XHProfRuns_Default') && '' !== $lib_path) {
    $data = xhprof_disable();
    require_once "{$lib_path}/xhprof_lib/utils/xhprof_lib.php";
    require_once "{$lib_path}/xhprof_lib/utils/xhprof_runs.php";
    $runs = new XHProfRuns_Default();
    $rt = $runs->save_run($data, $tag);
  }
  return $rt;
}

function profiler_flush(): void {
  $dir = \ini_get('xhprof.output_dir');
  foreach (glob($dir.'/*.xhprof') as &$file) unlink($file);
  echo "xhprof data cleared\n";
}
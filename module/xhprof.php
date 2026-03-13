<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

function profiler_start(): void{
  if (! \function_exists('xhprof_enable')) {
    return;
  }

  xhprof_enable(XHPROF_FLAGS_CPU | XHPROF_FLAGS_MEMORY);
}

function profiler_stop(string $tag = 'app'): string|bool|null{
  $rt = false;
  static $lib_path = null;
  if (\is_null($lib_path)) {
    global $server_cnf;
    $lib_path = $server_cnf['xhprof_lib_path'] ?? null;
  }

  if (! \function_exists('xhprof_enable')) {
    return false;
  }

  $data = xhprof_disable();
  if (! \is_null($lib_path)) {
    require_once $lib_path.'/xhprof_lib/utils/xhprof_lib.php';
    require_once $lib_path.'/xhprof_lib/utils/xhprof_runs.php';

    $runs = new XHProfRuns_Default(); //@phpstan-ignore-line
    $rt = $runs->save_run($data, $tag); //@phpstan-ignore-line
  }
  return $rt;
}

function profiler_flush(): void{
  $dir = \ini_get('xhprof.output_dir');

  foreach (glob($dir.'/*.xhprof') as $file) unlink($file);
  echo 'xhprof data cleared'.PHP_EOL;
}
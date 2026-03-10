<?php
// XZ Web Server by Fsb
define('ABSPATH', __DIR__);

// print_r(test_waf_load_tests());

// $id = $ldt['rule_id'] ?? 0;
// $tests = $ldt['tests'] ?? [];

// foreach ($tests as $test) {
//   test_id
//   desc
//   stages[0][input] headers method uri
// }

function test_waf_load_tests(): array|bool {
  $dir = './firewall/test/';
  $rt = [];
  if ($dh = \opendir($dir)){
    while (($file = \readdir($dh)) !== false){
      if (\in_array($file, ['.', '..'])) continue;
      $fpath = $dir.$file;
      
      if ('yaml' === \pathinfo($fpath, PATHINFO_EXTENSION)) {
        if ($tmp = test_waf_yml2arr($fpath)) {
          $rt[] = $tmp;
        } else {
          echo 'failed load and read: '.$fpath.PHP_EOL;
        }
      }
    }
    closedir($dh);
  }

  return $rt;
}

function test_waf_yml2arr(string $filename): array|bool {
  $rt = false;
  if (\is_file($filename)) {
    if (\function_exists('yaml_parse_file')) {
      $filen = $filename;
      $rt = yaml_parse_file($filen);
    
    } else {
      echo 'missing yaml extention, get it';
    }
  }
  return $rt;
}
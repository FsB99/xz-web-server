<?php
// XZ Web Server by Fsb
define('ABSPATH', __DIR__);

include './firewall_cnf.php';

test_waf_x();

function test_waf_x() {
  $tmp = [];
  $dt = test_waf_load_tests();

  foreach ($dt as $dtx) {
    $id = $dtx['rule_id'] ?? 0;
    $tests = $dtx['tests'] ?? [];

    foreach ($tests as $test) {
      $test_id = $test['test_id'] ?? 0;
      $desc = substr(($test['desc'] ?? ''), 0, 40);
      $stages = $test['stages'] ?? [];

      foreach ($stages as $stage) {
        $input = $stage['input'] ?? [];
        $headers = $input['headers'] ?? [];
        $method = $input['method'] ?? 'get';
        $uri = $input['uri'] ?? 'uri';

        if (test_waf_curl([
          'url' => $uri,
          'md' => $method,
          'headers' => $headers,
        ])) {
          echo "{$id}|{$test_id}|{$desc}: PASS".PHP_EOL;
        } else {
          echo "{$id}|{$test_id}|{$desc}: FAILED".PHP_EOL;
           $tmp[] = ['id' => $id, 'test_id' => $test_id, 'desc' => ($test['desc'] ?? '')];
        }
      }
    }
  }

  if (! empty($tmp)) {
    file_put_contents('./failed_tests.json', json_encode($tmp));
  }
}

function test_waf_curl(array $dt): bool {
  $rt = true;
  $path = $dt['url'] ?? '';
  $url = 'http://localhost:8080'.$path;
  $md = \strtolower($dt['md'] ?? 'get');
  $headers = $dt['headers'] ?? [];
  $posts = $dt['posts'] ?? null;
  $cuopt = [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => 3,
  ];

  if (! empty($url)) {
    $ch = curl_init($url);

    if ('post' === $md) {
      $cuopt[CURLOPT_POSTFIELDS] = $posts;
      $cuopt[CURLOPT_POST] = true;
    }

    if (! empty($headers)) {
      $cuopt[CURLOPT_HTTPHEADER] = $headers;
    }

    curl_setopt_array($ch, $cuopt);
    $resp = curl_exec($ch);
    $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if (200 === $status_code) {
      echo 'url: '.$url.' | '.$status_code.PHP_EOL;
      $rt = false;
    }
  }
  return $rt;
}

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
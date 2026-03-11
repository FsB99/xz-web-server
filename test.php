<?php
// XZ Web Server by Fsb
define('ABSPATH', __DIR__);
if (! \in_array(PHP_SAPI, ['cli', 'micro'])) exit('CLI only');

$copt = getopt("a:");
$copt_a = $copt['a'] ?? 'sast';

if ('waf' === $copt_a) {
  include './module/firewall_cnf.php';
  test_waf_dev();

} else {
  passthru('php vendor/bin/phpstan analyse -c ps.neon --memory-limit=1G');
}

function test_waf_dev() {
  global $crs_ignored_ids, $crs_test_must_http_code_200;

  $tmp = $reqs = [];
  $dt = test_waf_load_tests();

  // build array
  foreach ($dt as $dtx) {
    $id = $dtx['rule_id'] ?? 0;
    $tests = $dtx['tests'] ?? [];

    if (\in_array($id, $crs_ignored_ids)) continue;

    foreach ($tests as $test) {
      $test_id = $test['test_id'] ?? 0;
      $desc = substr(($test['desc'] ?? ''), 0, 40);
      $stages = $test['stages'] ?? [];

      foreach ($stages as $stage) {
        $input = $stage['input'] ?? [];

        $reqs[] = [
          'id' => $id,
          'test_id' => $test_id,
          'desc' => $desc,
          'url' => 'http://localhost:8080'.($input['uri'] ?? ''),
          'method' => $input['method'] ?? 'GET',
          'headers' => $input['headers'] ?? [],
        ];
      }
    }
  }

  // chunk
  $chunks = array_chunk($reqs, 5);

  foreach ($chunks as $chunk) {
    $mh = curl_multi_init();
    $chs = [];

    foreach ($chunk as $k => $r) {
      $ch = curl_init();
      curl_setopt_array($ch, [
        CURLOPT_URL => $r['url'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST => strtoupper($r['method']),
        CURLOPT_HTTPHEADER => $r['headers'],
        CURLOPT_TIMEOUT => 5,
        CURLOPT_NOSIGNAL => 1,
      ]);

      curl_multi_add_handle($mh, $ch);
      $chs[$k] = [$ch, $r];
    }

    do {
      $status = curl_multi_exec($mh, $running);
      curl_multi_select($mh);
    } while ($running && $status == CURLM_OK);

    foreach ($chs as [$ch, $meta]) {
      $err = curl_errno($ch);
      $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
      $exclude_this = (\in_array($meta['id'], $crs_test_must_http_code_200));

      if ($err || \in_array($code, [200])) {
        if ($exclude_this) {
          echo "{$meta['id']}|{$meta['test_id']}: {$code} Pass".PHP_EOL;
        } else {
          echo "{$meta['id']}|{$meta['test_id']}|{$meta['desc']}: {$code} [FAILED]".PHP_EOL;

          $tmp[] = [
            'id' => $meta['id'],
            'test_id' => $meta['test_id'],
            'desc' => $meta['desc']
          ];
        }
        
      } else {
        echo "{$meta['id']}|{$meta['test_id']}: {$code} Pass".PHP_EOL;
      }

      curl_multi_remove_handle($mh, $ch);
    }

    curl_multi_close($mh);
  }

  if (! empty($tmp)) {
    echo 'FAILED: '.\count($tmp).'/'.\count($reqs).PHP_EOL;
    @file_put_contents('./tmp/failed_tests.json', json_encode($tmp));
  }
}

function test_waf_load_tests(): array|bool {
  $dir = './module/firewall/test/';
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
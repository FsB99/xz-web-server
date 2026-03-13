<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

include ABSPATH.'/module/waf_cnf.php';
$waf_file = ABSPATH.'/module/waf_rules.php';

if (\is_file($waf_file)) {
  include $waf_file;
} else {
  echo 'Error: Failed to load waf rules'.PHP_EOL;
}

function waf_compile(array $rules): array{
  global $crs_ignored_ids, $crs_pl;
  $rt = [];
  $rules_added = 0;

  foreach ($rules as $r) {
    if (\in_array($r['id'], $crs_ignored_ids ?? []) || ($r['pl'] > $crs_pl)) continue;
    ++$rules_added;
    
    $cr = [
      'id' => $r['id'],
      'msg' => $r['msg'] ?? '',
      'score' => $r['score'] ?? 0,
      'conds' => []
    ];

    foreach ($r['rule'] as $c) {
      $vars = \array_map('strtolower', (array)($c['w'] ?? []));
      if (! $vars) continue;

      $cond = [
        'var' => $vars,
        'key' => $c['wpr'] ?? '',
        'op'  => null,
        'val' => null,
        'not' => ! empty($c['not'])
      ];

      foreach (['eq','not_eq','gt','empty','utf','byte_range','range','maxl','contains','rx','in'] as $op) {
        if (isset($c[$op])) {
          $cond['op'] = $op;
          $cond['val'] = $c[$op];
          break;
        }
      }

      if ($cond['op'] === 'in') {
        $set = [];
        foreach ((array)$cond['val'] as $v) {
          $set[strtolower($v)] = 1;
        }
        $cond['val'] = $set;
      }

      if ($cond['op'] === 'rx') {
        if (! valid_regex($cond['val'])) {
        // if (@preg_match($cond['val'], 'a') === false) {
          echo "Invalid regex in rule {$r['id']}".PHP_EOL;
          continue;
        }
      }

      $cr['conds'][] = $cond;
    }

    if (! $cr['conds']) continue;

    $cr['conds'] = waf_sort_conds($cr['conds']);
    $first = $cr['conds'][0]['var'][0] ?? null;

    $req_key = match($first) {
      'args' => 'r_args',
      'args_names' => 'r_args_names',
      'header' => 'r_head',
      'header_names' => 'r_head_names',
      'cookie' => 'r_cookie',
      'cookie_names' => 'r_cookie_names',
      'files' => 'r_files',
      'files_names' => 'r_files_names',
      'uri' => 'r_uri',
      'path' => 'r_path',
      'method' => 'r_mtd',
      'body' => 'r_body',
      'ip' => 'r_ip',
      default => null
    };

    if ($req_key) $rt[$req_key][] = $cr;
  }

  echo 'CRS loaded: '.$rules_added.PHP_EOL;
  // file_put_contents('tmp/compile.json', json_encode($rt));
  return $rt;
}

function waf_sort_conds(array $conds): array{
  static $prio = [
    'eq' => 1,
    'not_eq' => 1,
    'in' => 2,
    'contains' => 3,
    'maxl' => 4,
    'byte_range'=> 5,
    'range' => 5,
    'utf' => 6,
    'rx' => 10
  ];

  usort($conds, function($a,$b) use ($prio) {
    $pa = $prio[$a['op']] ?? 50;
    $pb = $prio[$b['op']] ?? 50;
    return $pa <=> $pb;
  });

  return $conds;
}

function waf_get_var(array $cond, array $req): array|null|string {
  $var = $cond['var'][0] ?? '';
  $key = \strtolower($cond['key'] ?? '');

  switch ($var) {
    case 'method':
    return $req['r_mtd'] ?? 'get';
   
    case 'uri':
      return $req['r_uri'] ?? '';
    
    case 'path':
      return $req['r_path'] ?? '';

    case 'ip':
      return $req['r_ip'] ?? '';

    case 'body':
      return $req['r_body'] ?? '';

    case 'header':
      if ($key) {
        return isset($req['r_head'][$key]) ? [$req['r_head'][$key]] : [];
      }
      return $req['r_head'] ?? [];

    case 'header_names':
      return $req['r_head_names'] ?? [];

    case 'cookie':
      if ($key) {
        return isset($req['r_cookie'][$key]) ? [$req['r_cookie'][$key]] : [];
      }
      return $req['r_cookie_vals'] ?? [];

    case 'cookie_names':
      return $req['r_cookie_names'] ?? [];

    case 'args':
      if ($key) {
        return isset($req['r_args'][$key]) ? [$req['r_args'][$key]] : [];
      }
      return $req['r_args_vals'] ?? [];

    case 'args_names':
      return $req['r_args_names'] ?? [];

    case 'files':
      if ($key) {
        return isset($req['r_files'][$key]) ? [$req['r_files'][$key]] : [];
      }
      return $req['r_files_vals'] ?? [];

    case 'files_names':
      return $req['r_files_names'] ?? [];
  }

  return null;
}

function waf_match_cond(array $cond, array $req): bool{
  $vals = waf_get_var($cond, $req);
  if (empty($vals) || \is_string($vals)) return false;
  $op  = $cond['op'];
  $val = $cond['val'];

  foreach ($vals as $v) { //@phpstan-ignore-line
    if ($v === '' || $v === null) continue;
    $r = false;

    switch ($op) {
      case 'eq':
        $r = (string)$v === (string)$val;
        break;

      case 'not_eq':
        $r = (string)$v !== (string)$val;
        break;

      case 'contains':
        $r = \str_contains(\strtolower($v), \strtolower($val));
        break;

      case 'maxl':
        $r = \strlen($v) > $val;
        break;

      case 'rx':
        $r = \preg_match($val, (string)$v);
        break;

      case 'in':
        $r = isset($val[(string)$v]);
        break;

      case 'byte_range':
        if (strpos($v, "\0") !== false) return false;
        break;

      case 'empty':
        $r = $v === '' || $v === null; //@phpstan-ignore-line
        break;

      case 'utf':
        $r = valid_utf8($v);
        break;
    }

    if (! empty($cond['not'])) $r = !$r;


    if ($r) return true;
  }
  return false;
}

function waf_run(array $req, int $threshold = 5): bool{
  static $CRS = null, $xhprof_on = null, $xhprof_ui = null;
  if (\is_null($xhprof_on)) {
    global $server_cnf;
    $check = $server_cnf['module_enabled'] ?? [];
    $check2 = $server_cnf['xhprof_scan'] ?? [];
    $xhprof_on = (\in_array('waf', $check2) && $check);
    $xhprof_ui = $server_cnf['xhprof_uiserver'] ?? '';
  }
  $score = 0;
  $hits = [];
  if ($xhprof_on) profiler_start();

  if (\is_null($CRS)) {
    global $crs_rules;
    $CRS = waf_compile($crs_rules);;
  }

  foreach ($CRS as $slot => $rules) {
    if (! isset($req[$slot]) || ! $req[$slot]) continue;

    foreach ($rules as $rule) {
      $conds = $rule['conds'];
      $ok = true;

      for ($i = 0, $n = \count($conds); $i < $n; $i++) {
        if (! waf_match_cond($conds[$i], $req)) {
          $ok = false;
          break;
        }
      }

      if (! $ok) continue;

      $score += $rule['score'];
      $hits[] = [
        'id' => $rule['id'],
        'msg' => $rule['msg'],
        'score' => $rule['score']
      ];

      if ($score >= $threshold) break 2;
    }
  }

  if ($xhprof_on) {
    if ($run = profiler_stop('waf')) {
      if (! \is_null($xhprof_ui)) {
        echo $xhprof_ui.'/index.php?run='.$run.'&source=waf'.PHP_EOL;
      } else {
        echo 'run='.$run.PHP_EOL;
      }
    }
  }

  if ($score >= $threshold) {
    /* debug output */
    // print_r([
    //   'waf'   => $hits,
    //   'score' => $score
    // ]);
    return true;
  }

  return false;
}

function waf_readfile(string $file): array {
  $rt = [];

  if (\is_file($file)) {
    $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    foreach ($lines as $line) {
      $line = \trim($line);
      if ('' === $line  || '#' === $line[0]) continue;
      $rt[] = $line;
    }
  }
  return $rt;
}

function waf_prepare_req(array &$req): void{
  if (!empty($req['r_head'])) {
    $req['r_head_vals'] = array_values($req['r_head']);
    $req['r_head_names'] = array_keys($req['r_head']);
  }

  if (!empty($req['r_cookie'])) {
    $req['r_cookie_vals'] = array_values($req['r_cookie']);
    $req['r_cookie_names'] = array_keys($req['r_cookie']);
  }

  if (!empty($req['r_args'])) {
    $req['r_args_vals'] = array_values($req['r_args']);
    $req['r_args_names'] = array_keys($req['r_args']);
  }

  if (!empty($req['r_post'])) {
    $req['r_post_vals'] = array_values($req['r_post']);
    $req['r_post_names'] = array_keys($req['r_post']);
  }

  if (!empty($req['r_get'])) {
    $req['r_get_vals'] = array_values($req['r_get']);
    $req['r_get_names'] = array_keys($req['r_get']);
  }

  if (!empty($req['r_post'])) {
    $req['r_post_vals'] = array_values($req['r_post']);
    $req['r_post_names'] = array_keys($req['r_post']);
  }

  if (!empty($req['r_files'])) {
    $req['r_files_vals'] = array_values($req['r_files']);
    $req['r_files_names'] = array_keys($req['r_files']);
  }
}

function valid_regex(string $pattern): bool {
  static $eh = null;
  if (\is_null($eh)) $eh = function(){};

  set_error_handler($eh, E_WARNING);
  $ok = preg_match($pattern, '') !== false;
  restore_error_handler();
  return $ok;
}

function valid_utf8(string $s): bool{
  $utf = ('' === $s || (preg_match('/^./us', $s) === 1));
  // echo 'utf: '.($utf ? 1 : 0).PHP_EOL;
  return $utf;
}
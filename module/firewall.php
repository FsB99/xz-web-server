<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

include './module/firewall_cnf.php';
$firewall_file = './module/firewall_rules.php';

if (\is_file($firewall_file)) {
  include $firewall_file;
} else {
  echo 'Error: Failed to load firewall rules'.PHP_EOL;
}

function firewall_compile(array $rules): array {
  global $crs_ignored_ids;
  $rt = [];

  foreach ($rules as $r) {
    $cr = [
      'id' => $r['id'],
      'msg' => $r['msg'] ?? '',
      'score' => $r['score'] ?? 0,
      'conds' => []
    ];

    if (in_array($r['id'], $crs_ignored_ids)) continue;

    foreach ($r['rule'] as $c) {
      $vars = (array) ($c['w'] ?? []);
      if (!$vars) continue;

      $cond = [
        'var' => $vars,
        'key' => isset($c['wpr']) ? strtolower($c['wpr']) : '',
        'op'  => 'default',
        'val' => null,
      ];

      foreach (['eq','not_eq','gt','empty','utf','byte_range','range','maxl','contains','rx','in'] as $op) {
        if (isset($c[$op])) {
          $cond['op'] = $op;
          $cond['val'] = $c[$op];
          break;
        }
      }

      // handle 'in' as associative set
      if ($cond['op'] === 'in') {
        $set = [];
        foreach ((array)$cond['val'] as $v) $set[$v] = 1;
        $cond['val'] = $set;
      }

      // keep regex as string only
      if ($cond['op'] === 'rx') {
        if (@preg_match($cond['val'], 'a') === false) {
          echo "Invalid regex: {$r['id']}" . PHP_EOL;
          continue;
        }
      }

      $cr['conds'][] = $cond;
    }

    // group by request key
    foreach ($cr['conds'] as $cond) {
      foreach ($cond['var'] as $v) {
        $req_key = match(strtolower($v)) {
          'args','get','args_names' => 'r_get',
          'post' => 'r_post',
          'header','request_headers' => 'r_head',
          'cookie' => 'r_cookie',
          'files' => 'r_files',
          'uri','request_uri' => 'r_uri',
          'path' => 'r_path',
          'method','request_method' => 'r_mtd',
          'body','request_body' => 'r_body',
          'ip','remote_addr' => 'r_ip',
          default => null
        };

        if ($req_key) {
          $rt[$req_key][] = [
            'id' => $cr['id'],
            'msg' => $cr['msg'],
            'score' => $cr['score'],
            'cond' => $cond
          ];
        }
      }
    }
  }

  // file_put_contents('./tmp/compile.json', json_encode($rt));
  return $rt;
}

function firewall_get_var(array $req, string $var, string $key): array|string|null {
  switch ($var) {
    case 'req_line':
      return ($req['r_mtd'] ?? '') . ' ' . ($req['r_uri'] ?? '') . ' HTTP/1.1';
    case 'uri':
      return $req['r_uri'] ?? null;
    case 'path':
      return $req['r_path'] ?? null;
    case 'method':
      return $req['r_mtd'] ?? 'get';
    case 'body':
      return $req['r_body'] ?? null;

    // Arrays
    case 'args':
    case 'args_names':
    case 'args_get':
    case 'args_post':
    case 'cookie':
    case 'cookie_names':
    case 'files':
    case 'files_names':
    case 'header':
    case 'header_names':
      $map = [
        'args' => 'r_get',
        'args_names' => 'r_get',
        'args_get' => 'r_get',
        'args_post' => 'r_post',
        'cookie' => 'r_cookie',
        'cookie_names' => 'r_cookie',
        'files' => 'r_files',
        'files_names' => 'r_files',
        'header' => 'r_head',
        'header_names' => 'r_head',
      ];

      $arr = $req[$map[$var]] ?? [];

      if ($key !== '' && isset($arr[$key])) {
        if (str_ends_with($var,'_names')) return [$key];
        return is_array($arr[$key]) ? $arr[$key] : [$arr[$key]];
      }

      if (str_ends_with($var,'_names')) return array_keys($arr);
      return array_values($arr);
  }

  return null;
}

function firewall_match_cond(array $cond, array $req): bool {
  foreach ($cond['var'] as $var) {
    $values = firewall_get_var($req, $var, $cond['key']);
    if ($values === null) continue;
    if (!is_array($values)) $values = [$values];

    foreach ($values as $v) {
      if ($v === null) continue;

      $ok = false;
      switch ($cond['op']) {
        case 'utf':
          $ok = valid_utf8($v);
          break;
        case 'byte_range':
          $ok = valid_byte_range($v, $cond['val'][0], $cond['val'][1]);
          break;
        case 'eq':
          $ok = $v === $cond['val'];
          break;
        case 'not_eq':
          $ok = $v !== $cond['val'];
          break;
        case 'gt':
          $ok = $v > $cond['val'];
          break;
        case 'in':
          $ok = isset($cond['val'][strtoupper((string)$v)]);
          break;
        case 'range':
          $ok = $v >= $cond['val'][0] && $v <= $cond['val'][1];
          break;
        case 'maxl':
          $ok = strlen($v) <= $cond['val'];
          break;
        case 'contains':
          $ok = str_contains((string)$v, $cond['val']);
          break;
        case 'rx':
          $ok = preg_match($cond['val'], $v) === 1;
          break;
        default:
          $ok = false;
      }

      if (! empty($cond['not'])) $ok = !$ok;
      if (! $ok) return false; // fail fast
    }
  }
  return true;
}

function firewall_run(array $req, int $threshold = 5): bool {
  static $CRS = null;
  if (\is_null($CRS)) {
    global $crs_rules;
    $CRS = firewall_compile($crs_rules);
  }
  $score = 0;
  $hits = $msgs = [];

  foreach ($CRS as $req_key => $rules) {
    foreach ($rules as $rule) {
      if (!isset($rule['conds']) || ! \is_array($rule['conds'])) continue;
      $matched = true;
      
      foreach ($rule['conds'] as $cond) {
        if (! firewall_match_cond($cond, $req)) {
          $matched = false;
          break;
        }
      }

      if (!$matched) continue;

      $score += $rule['score'];
      $hits[] = $rule['id'];
      $msgs[] = $rule['msg'];

      if ($score >= $threshold) break 2;
    }
  }

  if ($score >= $threshold) {
    // debug
    // print_r([
    //     'id' => $hits,
    //     'msg' => $msgs,
    // ]);
    return true;
  }

  return false;
}

function firewall_readfile(string $file): array {
  $rt = [];

  if (\is_file($file)) {
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    foreach ($lines as $line) {
      $line = \trim($line);
      if ('' === $line  || '#' === $line[0]) continue;
      $rt[] = $line;
    }
  }
  return $rt;
}

function valid_byte_range(string $s, int $min = 1, int $max = 255): bool{
  $len = \strlen($s);
  for ($i = 0; $i < $len; $i++) {
    $b = \ord($s[$i]);
    if ($b < $min || $b > $max) return false;
  }
  return true;
}

function valid_utf8(string $s): bool{
  $utf = ('' === $s || (preg_match('/^./us', $s) === 1));
  echo 'utf: '.($utf ? 1 : 0).PHP_EOL;
  return $utf;
}

function valid_regex(string $pattern): bool {
  static $eh = null;
  if (\is_null($eh)) $eh = function(){};

  set_error_handler($eh, E_WARNING);
  $ok = preg_match($pattern, '') !== false;
  restore_error_handler();
  return $ok;
}

if (! \function_exists('array_is_list')) {
  function array_is_list(array $arr): bool {
    $i = 0;
    foreach ($arr as $k => $_) {
      if ($k !== $i++) return false;
    }
    return true;
  }
}
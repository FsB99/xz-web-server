<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

$firewall_file = './module/firewall_rules.php';

if (\is_file($firewall_file)) {
  include $firewall_file;
} else {
  echo 'Error: Failed to load firewall rules'.PHP_EOL;
}

function firewall_compile(array $rules): array{
  $rt = [1 => [], 2 => []];

  foreach ($rules as $r) {
    $phase = $r['phase'] ?? 1;
    if ($phase > 2) continue;

    $cr = [
      'id' => $r['id'],
      'score' => $r['score'] ?? 0,
      'conds' => []
    ];

    foreach ($r['rule'] as $c) {
      $vars = (array) ($c['w'] ?? '');

      $cond = [
        'var' => $vars,
        'key' => strtolower($c['wpr'] ?? '')
      ];

      if (isset($c['not'])) {
        $cond['not']  = $c['not'];
      }

      if (isset($c['eq'])) {
        $cond['op']  = 'eq';
        $cond['val'] = $c['eq'];

      } elseif (isset($c['maxl'])) {
        $cond['op']  = 'maxl';
        $cond['val'] = $c['maxl'];

      } elseif (isset($c['in'])) {
        $set = [];

        foreach ($c['in'] as $v) $set[strtoupper($v)] = 1;

        $cond['op']  = 'in';
        $cond['val'] = $set;

      } elseif (isset($c['contains'])) {
        $cond['op']  = 'contains';
        $cond['val'] = $c['contains'];

      } elseif (isset($c['rx'])) {
        $cond['op']  = 'rx';
        $cond['val'] = $c['rx'];

      } else {
        continue;
      }

      $cr['conds'][] = $cond;
    }

    $rt[$phase][] = $cr;
  }

  return $rt;
}

function firewall_get_var(array $req, string $var, string $key): array|string|null{
  return match ($var) {
    'method' => $req['r_mtd'] ?? 'get',
    'uri' => $req['r_uri'] ?? null,
    'path' => $req['r_path'] ?? null,
    'body' => $req['r_body'] ?? null,
    'header' => $req['r_head'][$key] ?? null,
    'header_name' => array_keys($req['r_head']) ?? null,
    'cookie' => $req['r_cookie'][$key] ?? null,
    'cookie_name' => isset($req['r_cookie']) ? array_keys($req['r_cookie']) : null,
    'get' => $req['r_get'][$key] ?? null,
    'get_name' => isset($req['r_get']) ? array_keys($req['r_get']) : null,
    'post' => $req['r_post'][$key] ?? null,
    'get_name' => isset($req['r_post']) ? array_keys($req['r_get']) : null,
    default => null
  };
}

function firewall_match_cond(array $cond, array $req): bool{
  foreach ($cond['var'] as $var) {
    $v = firewall_get_var($req, $var, $cond['key']);
    if ($v === null) continue;

    // debug
    // print_r($v);
    // echo PHP_EOL;

    if (is_array($v)) {
      // flat array
      $pass = true;
      if ($flat_ar = firewall_array_is_flat($v)) {
        foreach ($v as $vv) {
          $ok = match ($cond['op']) {
            'eq' => $vv === $cond['val'],
            'in' => (bool) isset($cond['val'][\strtoupper($vv)]),
            'maxl' => \strlen($vv) > $cond['val'],
            'contains' => \str_contains($vv, $cond['val']),
            'rx' => (bool) \preg_match($cond['val'], $vv),
            default => false,
          };

          // invert logic if 'not' is set
          if (! empty($cond['not'])) $ok = !$ok;
          if (! $ok) {
            $pass = false;
            break;
          }
        }

        return $pass;
      
      // associative array
      } else {
        $pass = true;
        foreach ($v as $k => $vv) {
          // key 
          $ok_key = match ($cond['op']) {
            'eq' => $k === $cond['val'],
            'in' => (bool) isset($cond['val'][\strtoupper($k)]),
            'maxl' => \strlen($k) > $cond['val'],
            'contains' => \str_contains($k, $cond['val']),
            'rx' => (bool) \preg_match($cond['val'], $k),
            default => false,
          };

          // invert logic if 'not' is set
          if (! empty($cond['not'])) $ok_key = !$ok_key;
          if (! $ok_key) {
            $pass = false;
            break;
          }

          // value 
          $ok_value = match ($cond['op']) {
            'eq' => $vv === $cond['val'],
            'in' => (bool) isset($cond['val'][\strtoupper($vv)]),
            'maxl' => \strlen($vv) > $cond['val'],
            'contains' => \str_contains($vv, $cond['val']),
            'rx' => (bool) \preg_match($cond['val'], $vv),
            default => false,
          };

          // invert logic if 'not' is set
          if (! empty($cond['not'])) $ok_value = !$ok_value;
          if (! $ok_value) {
            $pass = false;
            break;
          }
        }
      }

    } else {
      $ok = match ($cond['op']) {
        'eq' => $v === $cond['val'],
        'in' => (bool) isset($cond['val'][\strtoupper($v)]),
        'maxl' => \strlen($v) > $cond['val'],
        'contains' => \str_contains($v, $cond['val']),
        'rx' => (bool) \preg_match($cond['val'], $v),
        default => false,
      };

      // invert logic if 'not' is set
      if (! empty($cond['not'])) $ok = !$ok;
      if ($ok) return true;
    }
  }

  return false;
}

function firewall_run(array $req): bool{
  $rt = false;
  static $CRS = null;
  $score = 0;
  $hits  = [];
  $threshold = 5;
  if (\is_null($CRS)) {
    global $crs_rules;
    $CRS = firewall_compile($crs_rules);
  }

  foreach ([1,2] as $phase) {
    foreach ($CRS[$phase] as $rule) {
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

      if ($score >= $threshold) break 2;
    }
  }

  if ($score >= $threshold) {
    // todo, maybe log this, but for now just print on CLI
    // $rs = [
    //   'score' => $score,
    //   'hits' => $hits,
    //   'blocked' => $score >= $threshold
    // ];
    // print_r($rs);
    $rt = true;
  }
  return $rt;
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

function firewall_array_is_flat(array $array): bool {
  return array_keys($array) === range(0, count($array) - 1);
}
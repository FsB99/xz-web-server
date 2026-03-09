<?php
// XZ Web Server by Fsb

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
      $cond = [
        'var' => $c['w'],
        'key' => strtolower($c['wpr'] ?? '')
      ];

      if (isset($c['eq'])) {
        $cond['op']  = 'eq';
        $cond['val'] = $c['eq'];

      } elseif (isset($c['in'])) {
        $set = [];

        foreach ($c['in'] as $v) $set[$v] = 1;

        $cond['op']  = 'in';
        $cond['val'] = $set;

      } elseif (isset($c['contains'])) {
        $cond['op']  = 'contains';
        $cond['val'] = $c['contains'];

      } elseif (isset($c['rx'])) {
        $cond['op']  = 'rx';
        $cond['val'] = $c['rx'];

      } else {
        // invalid rule, skip safely
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
    'method' => $req['r_mtd'],
    'uri' => $req['r_uri'],
    'path' => $req['r_path'],
    'body' => $req['r_body'],
    'header' => $req['r_head'][$key] ?? null,
    'cookie' => $req['r_cookie'][$key] ?? null,
    'get' => $req['r_get'][$key] ?? null,
    'post' => $req['r_post'][$key] ?? null,
    default => null
  };
}

function firewall_match_cond(array $cond, array $req): bool{
  $v = firewall_get_var($req, $cond['var'], $cond['key']);

  if ($v === null) return false;

  return match ($cond['op']) {
    'eq' => $v === $cond['val'],
    'in' => isset($cond['val'][$v]),
    'contains' => \str_contains($v, $cond['val']),
    'rx' => (bool) \preg_match($cond['val'], $v),
    default => false
  };
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
      foreach ($rule['conds'] as $cond) {
        if (! firewall_match_cond($cond, $req)) continue 2;
      }

      $score += $rule['score'];
      $hits[] = $rule['id'];

      if ($score >= $threshold) break 2;
    }
  }

  if ($score >= $threshold) {
    // maybe log this crap.
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
<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

global $server_cnf;
$server_cnf['workers'] = cpu_count();
$__clients = $__buffers = $__offsets = [];

const resp_static = "HTTP/1.1 200 OK\r\n"."Content-Length: 5\r\n"."Connection: keep-alive\r\n\r\n"."hello";

function server_start(string $host, int $port, int $workers): void {
  static $os = null, $ev = null, $pcntl = null;
  if (\is_null($pcntl)) {
    global $server_cnf;
    $os = $server_cnf['os'] ?? 'unix';
    $pcntl = $server_cnf['ext_pcntl'] ?? false;
    $ev = $server_cnf['ext_ev'] ?? false;
  }

  echo ascii_table([
    [
      ['text' => 'XZ Web Server', 'colspan' => 4]
    ],
  ], [
    [
      ['text' => 'OS'],
      ['text' => $os],
      ['text' => 'Worker'],
      ['text' => $workers],
    ],
    [
      ['text' => 'Pcntl'],
      ['text' => ($pcntl ? 'ok' : '-')],
      ['text' => 'Ev'],
      ['text' => ($ev ? 'ok' : '-')],
    ],
  ], [
    [
      ['text' => 'http://'.(\in_array($host, ['0.0.0.0', '127.0.0.1']) ? 'localhost' : $host).':'.$port, 'colspan' => 4]
    ]
  ]);

  if ($pcntl && 'unix' === $os && $workers > 1) {
    for ($i = 0; $i < $workers; ++$i) {
      $pid = pcntl_fork();

      if (0 === $pid) {
        server_run($host, $port);
        exit;
      }
    }

    while (pcntl_wait($status) > 0);
  
  } else {
    server_run($host, $port);
  }
}

function server_run(string $host, int $port): void {
  static $ev = null;
  if (\is_null($ev)) {
    global $server_cnf;
    $ev = $server_cnf['ext_ev'] ?? false;
  }

  $context = stream_context_create([
    'socket' => [
      'so_reuseport' => true,
      'backlog' => 2048,
    ],
  ]);

  $server = stream_socket_server("tcp://{$host}:{$port}", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);

  if (! $server) die("Server error: {$errstr}".PHP_EOL);
  stream_set_blocking($server, false);
  // echo "Worker PID: ".getmypid().PHP_EOL;

  if ($ev) {
    loop_ev($server);
  } else {
    loop_select($server);
  }
}

function loop_ev($server): void {
  static $max_header_size = null, $server_idle = null, $waf_on = null;
  static $watchers = [];
  if (\is_null($max_header_size)) {
    global $server_cnf;
    $max_header_size = $server_cnf['max_header_size'] ?? 8192;
    $server_idle = $server_cnf['idle_second'] ?? 10;
  }
  if (\is_null($waf_on)) {
    global $server_cnf;
    $module_enabled = $server_cnf['module_enabled'] ?? [];
    
    if (\in_array('waf', $module_enabled)) $waf_on = true;
  }
  
  $loop = EvLoop::defaultLoop();
  $watchers['server'] = $loop->io($server, Ev::READ, function ($w) use ($server, $loop, &$watchers, $max_header_size, &$server_idle, &$waf_on) {
    while ($client = @stream_socket_accept($server, 0)) {
      stream_set_blocking($client, false);
      $timerWatcher = null;
      $state = [
        'sock'   => $client,
        'buffer' => '',
        'offset' => 0,
        'timer'  => null,
      ];

      $watcher = $loop->io($client, Ev::READ, function ($cw) use ($max_header_size, $watchers, $waf_on) {
        $state = &$cw->data;
        $sock  = $state['sock'];

        if ($state['timer']) $state['timer']->again();
        $data = @fread($sock, 8192);

        if ('' === $data || false === $data) {
          if ($state['timer']) $state['timer']->stop();

          $cw->stop();
          if (\is_resource($sock)) fclose($sock);
          unset($watchers[(int)$sock]);
          return;
        }

        $state['buffer'] .= $data;

        if (\strlen($state['buffer']) > $max_header_size) {
          drop_connection($sock, 413);
          $cw->stop();
          return;
        }

        while (true) {
          $req = parse_request($state['buffer'], $state['offset']);
          if (\is_null($req)) break;

          if (isset($req['__invalid'])) {
            drop_connection($sock, $req['__invalid']);
            
            if ($state['timer']) $state['timer']->stop();
            $cw->stop();
            unset($watchers[(int)$sock]);
            return;
          }

          if ($waf_on) {
            waf_prepare_req($req);
            if (waf_run($req)) {
              drop_connection($sock, 401);
              $cw->stop();
              return;
            }
          }

          handle_req($sock, $req, $state);
        }
      });

      $timerWatcher = $loop->timer(
        $server_idle,
        0,
        function ($tw) use (&$watcher, $client, $watchers) {
          $watcher->stop();
          if (\is_resource($client)) fclose($client);
          unset($watchers[(int)$client]);
        }
      );

      $state['timer'] = $timerWatcher;
      $watcher->data = $state;
      $watchers[(int)$client] = $watcher;
    }
  });

  $loop->run();
}

function loop_select($server): void {
  global $__clients, $__buffers, $__offsets;
  static $max_header_size = null, $waf_on = null;
  if (\is_null($max_header_size)) {
    global $server_cnf;
    $max_header_size = $server_cnf['max_header_size'] ?? 8192;
  }
  if (\is_null($waf_on)) {
    global $server_cnf;
    $module_enabled = $server_cnf['module_enabled'] ?? [];
    if (\in_array('waf', $module_enabled)) $waf_on = true;
  }

  while (true) { //@phpstan-ignore-line
    $write = $except = [];
    $read = [$server];
    foreach ($__clients as $c) $read[] = $c;

    if (false === stream_select($read, $write, $except, null)) continue;

    foreach ($read as &$sock) {
      if ($sock === $server) {
        $client = stream_socket_accept($server, 0);

        if ($client) {
          stream_set_blocking($client, false);
          $id = (int)$client;
          $__clients[$id] = $client;
          $__buffers[$id] = '';
          $__offsets[$id] = 0;
        }
        continue;
      }

      $id = (int)$sock;
      $data = fread($sock, 8192);

      if ('' === $data || false === $data) {
        if (\is_resource($sock)) fclose($sock);
        unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
        continue;
      }

      $__buffers[$id] .= $data;

      if (\strlen($__buffers[$id]) > $max_header_size) {
        drop_connection($sock, 413);
        if (\is_resource($sock)) fclose($sock);
        unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
        continue;
      }

      while (true) {
        $req = parse_request($__buffers[$id], $__offsets[$id]);
        if (\is_null($req)) break;

        if (isset($req['__invalid'])) {
          drop_connection($sock, $req['__invalid']);
          if (\is_resource($sock)) fclose($sock);
          unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
          break;
        }

        if ($waf_on) {
          waf_prepare_req($req);
          if (waf_run($req)) {
            drop_connection($sock, 401);
            if (\is_resource($sock)) fclose($sock);
            unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
            break;
          }
        }

        handle_req($sock, $req, ['timer' => null]);

        if (isset($req['r_close']) && $req['r_close']) {
          if (\is_resource($sock)) fclose($sock);
          unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
          break;
        }
      }
    }
  }
}

function parse_request(string &$buffer, int &$offset): ?array {
  static $max_header_size = null, $max_body_size = null, $max_uri_length = null;

  if ($max_header_size === null) {
    global $server_cnf;
    $max_header_size = $server_cnf['max_header_size'];
    $max_body_size   = $server_cnf['max_body_size'];
    $max_uri_length  = $server_cnf['max_uri_length'];
  }

  $len = \strlen($buffer);
  $headers = $cookies = $get = $post = $files = [];
  $header_end = strpos($buffer, "\r\n\r\n", $offset);

  if ($header_end === false) {
    if ($len > $max_header_size) return ['__invalid'=>413];
    return null;
  }

  $header_end += 4;
  if ($header_end > $max_header_size) return ['__invalid'=>413];
  $line_end = \strpos($buffer, "\r\n", $offset);
  if ($line_end === false) return ['__invalid'=>400];
  $request_line = \substr($buffer,$offset,$line_end-$offset);
  $parts = \explode(' ',$request_line,3);
  if (\count($parts) !== 3) return ['__invalid'=>400];
  [$method,$uri,$http] = $parts;
  $method = \strtoupper($method);
  static $allowed = ['GET'=>1,'HEAD'=>1,'POST'=>1,'PUT'=>1,'DELETE'=>1,'OPTIONS'=>1,'TRACE'=>1,'CONNECT'=>1,'PATCH'=>1];

  if (!isset($allowed[$method])) return ['__invalid'=>405];
  if (strlen($uri) > $max_uri_length || strpos($uri,"\0") !== false) return ['__invalid'=>414];
  if ($http !== 'HTTP/1.1' && $http !== 'HTTP/1.0') return ['__invalid'=>400];
  $qpos = \strpos($uri,'?');
  $path = $qpos === false ? $uri : \substr($uri,0,$qpos);
  $query_str = $qpos === false ? '' : \substr($uri,$qpos+1);
  $content_length = 0;
  $content_length_seen = false;
  $transfer_encoding_seen = false;
  $h_start = $line_end + 2;

  while ($h_start < $header_end-2) {
    $h_end = strpos($buffer,"\r\n",$h_start);
    if ($h_end === false) break;

    $line = \substr($buffer,$h_start,$h_end-$h_start);
    $colon = \strpos($line,':');
    if ($colon === false) return ['__invalid'=>400];
    $key = strtolower(trim(substr($line,0,$colon)));
    $val = trim(substr($line,$colon+1));
    if ($key === '' || strspn($key,"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz") !== strlen($key)) return ['__invalid'=>400];
    if (str_contains($val,"\r") || str_contains($val,"\n")) return ['__invalid'=>400];
    if ($key === 'transfer-encoding') $transfer_encoding_seen = true;

    if ($key === 'content-length') {
      if (!preg_match('/^\d+$/',$val)) return ['__invalid'=>400];
      $cl = (int)$val;
      if ($content_length_seen && $cl !== $content_length) return ['__invalid'=>400];
      if ($cl > $max_body_size) return ['__invalid'=>413];
      $content_length_seen = true;
      $content_length = $cl;
    }

    if (isset($headers[$key])) {
      $headers[$key] .= ',' . $val;
    } else {
      $headers[$key] = $val;
    }

    if ($key === 'cookie') parse_kv(str_replace('; ','&',$val),$cookies);
    $h_start = $h_end + 2;
  }

  if ($transfer_encoding_seen) return ['__invalid'=>501];
  if ($http === 'HTTP/1.1' && !isset($headers['host'])) return ['__invalid'=>400];
  $total = $header_end + $content_length;
  if ($len < $total) return null;
  $body = $content_length ? \substr($buffer,$header_end,$content_length) : '';
  if ($query_str !== '') parse_kv($query_str,$get);

  if ($method === 'POST' && $content_length > 0 && isset($headers['content-type'])) {
    $ctype = strtolower($headers['content-type']);
    if (str_contains($ctype,'application/x-www-form-urlencoded')) {
      parse_kv($body,$post);
    } elseif (str_contains($ctype,'multipart/form-data')) {
      parse_multipart($body,$ctype,$post,$files);
    }
  }

  $buffer = \substr($buffer,$total);
  $args = $get;
  if ($post) $args = \array_merge($args,$post);

  $rt = [
    'r_ver'=>$http,
    'r_head'=>$headers,
    'r_ip'=>null,
    'r_cookie'=>$cookies,
    'r_uri'=>$uri,
    'r_path'=>$path,
    'r_mtd'=>strtolower($method),
    'r_files'=>$files,
    'r_args'=>$args,
    'r_get'=>$get,
    'r_post'=>$post,
    'r_body'=>$body,
    'r_close'=>isset($headers['connection']) && strtolower($headers['connection'])==='close',
    'r_expect_continue'=>isset($headers['expect']) && strtolower($headers['expect'])==='100-continue'
  ];

  // print_r($rt);
  return $rt;
}

function parse_kv(string $input, array &$out): void {
  foreach (\explode('&', $input) as $pair) {
    $eq = \strpos($pair, '=');
    if (false === $eq) continue;
    $k = \urldecode(\substr($pair, 0, $eq));
    $v = \urldecode(\substr($pair, $eq + 1));
    $out[$k] = $v;
  }
}

function parse_multipart(string $body, string $ctype, array &$post, array &$files): void {
  if (! preg_match('/boundary=(.+)$/', $ctype, $m)) return;
  $boundary = '--'.$m[1];
  $parts = \explode($boundary, $body);
  array_pop($parts); // trailing --
  array_shift($parts); // preamble

  foreach ($parts as $p) {
    $h = [];
    $p = \ltrim($p, "\r\n");
    if ('' === $p) continue;
    [$header_str, $content] = \explode("\r\n\r\n", $p, 2) + ['', ''];
    $content = \rtrim($content, "\r\n");
    
    foreach (\explode("\r\n", $header_str) as $line) {
      $cpos = \strpos($line, ':');
      if (false !== $cpos) $h[\strtolower(\trim(\substr($line,0,$cpos)))] = \trim(\substr($line,$cpos+1));
    }
    if (! isset($h['content-disposition'])) continue;
    if (! preg_match('/name="([^"]+)"/', $h['content-disposition'], $nm)) continue;
    $name = $nm[1];
    if (preg_match('/filename="([^"]*)"/', $h['content-disposition'], $fn)) {
      $filename = $fn[1];
      $files[$name] = ['name' => $filename, 'body' => $content];
    } else {
      $post[$name] = $content;
    }
  }
}

function http_status_code(): array {
  static $rt = [
    200 => '200 OK',
    201 => '201 Created',
    204 => '204 No Content',
    301 => '301 Moved Permanently',
    302 => '302 Found',
    400 => '400 Bad Request',
    401 => '401 Unauthorized',
    403 => '403 Forbidden',
    404 => '404 Not Found',
    405 => "405 Method Not Allowed",
    408 => "408 Request Timeout",
    413 => "413 Payload Too Large",
    414 => "414 URI Too Long",
    500 => '500 Internal Server Error',
    501 => "501 Not Implemented",
  ];
  return $rt;
}

function handle_req($sock, array $req, array $state): void {
  static $base = "HTTP/1.1 ";
  static $status = null, $xhprof_on = null, $xhprof_ui = null;
  if (\is_null($status)) {
    global $server_cnf;
    $status = http_status_code();
    $check = $server_cnf['module_enabled'] ?? [];
    $check2 = $server_cnf['xhprof_scan'] ?? [];
    $xhprof_on = (\in_array('http', $check2) && $check);
    $xhprof_ui = $server_cnf['xhprof_uiserver'] ?? '';
  }
  $close = false;
  if ($xhprof_on) profiler_start();

  if (! empty($req['r_expect_continue'])) fwrite($sock, "HTTP/1.1 100 Continue\r\n\r\n");

  $dt = route_run($req);
  $body = $dt['r_body'];
  $code   = $dt['r_code'] ?? 200;
  $hdr_ar = $dt['r_header'] ?? [];  
  $status_line = $base.($status[$code] ?? ($code . " OK"))."\r\n";
  $len = \strlen($body);
  $headers = $status_line."Content-Length: {$len}\r\n";
  $close = ('HTTP/1.0' === $req['r_ver']) ? (! isset($req['r_head']['connection']) || \strtolower($req['r_head']['connection']) !== 'keep-alive') : $req['r_close'];

  foreach ($hdr_ar as $k => $v) $headers .= $k . ": " . $v . "\r\n";

  $headers .= ($close) ? "Connection: close\r\n" : "Connection: keep-alive\r\n";
  $headers .= "Date: " . gmdate('D, d M Y H:i:s') . " GMT\r\n";
  $headers .= "Server: XLNZ\r\n";
  $headers .= "\r\n";
  $response = ($req['r_mtd'] === 'head') ? $headers : $headers . $body;
  $written = 0;

  if ($req['r_mtd'] !== 'head') $response .= $body;
  $total = \strlen($response);

  while ($written < $total) {
    $n = @fwrite($sock, \substr($response, $written));
    if (false === $n || 0 === $n) break;
    $written += $n;
  }

  if ($close) {
    if (! empty($state['timer'])) $state['timer']->stop();
    if (\is_resource($sock)) fclose($sock);
  }

  if ($xhprof_on) {
    if ($run = profiler_stop('http')) {
      if (! \is_null($xhprof_ui)) {
        echo $xhprof_ui.'/index.php?run='.$run.'&source=http'.PHP_EOL;
      } else {
        echo 'run='.$run.PHP_EOL;
      }
    }
  }
}

function drop_connection($sock, int $code): void {
  static $code_ar = null;
  $code_ar ??= http_status_code();
  $msg = $code_ar[$code] ?? "400 Bad Request";
  $body = $msg;
  $out = "HTTP/1.1 $code $msg\r\n";
  $out .= "Content-Length: ".strlen($body)."\r\n";
  $out .= "Connection: close\r\n\r\n";
  $out .= $body;

  fwrite($sock, $out);
  if (\is_resource($sock)) fclose($sock);
}

function should_close(string $http, array $headers): bool {
  $conn = \strtolower($headers['connection'] ?? '');
  if ('HTTP/1.0' === $http) return $conn !== 'keep-alive';
  return $conn === 'close';
}

function cpu_count(): int{
  $rt = 1;
  if (0 === \stripos(PHP_OS, 'WIN')) {
    $out = shell_exec('wmic cpu get NumberOfCores /value');
    if ($out && \is_string($out) && preg_match('/NumberOfCores=(\d+)/', $out, $m)) { //@phpstan-ignore-line
      $rt = (int) $m[1];
    }
  
  } elseif (\is_file('/proc/cpuinfo')) {
    if ($res = @file_get_contents('/proc/cpuinfo')) {
      $rt = max(1, \substr_count($res, 'processor'));
    }
    
  } elseif (\function_exists('shell_exec')) {
    $res = shell_exec('sysctl -n hw.ncpu 2>/dev/null');
    if ($res && \is_numeric($res)) {
      $rt = (int) $res;
    }
  }
  return $rt;
}

function route_compile_static(): array {
  global $routes;
  $rt = [];

  foreach ($routes as $r) {
    if (false === \strpos($r['path'], '{')) {
      $method = \strtolower($r['m']);
      $rt[$method][$r['path']] = $r;
    }
  }
  return $rt;
}

function route_compile(): array {
  global $routes;
  $rt = [];

  foreach ($routes as $r) {
    $method = \strtolower($r['m'] ?? 'get');
    $path = \trim($r['path'] ?? '/', '/');
    $rt[$method] ??= ['s' => [], 'w' => null, 'r' => null];
    $node = &$rt[$method];
    $segs = $path === '' ? [] : \explode('/', $path);

    foreach ($segs as $seg) {
      if ($seg[0] === '{' && \substr($seg, -1) === '}') {
        $param = \substr($seg, 1, -1);

        if (\is_null($node['w'])) {
          $node['w'] = [
            'p' => $param,
            's' => [],
            'w' => null,
            'r' => null,
          ];
        }

        $node = &$node['w'];
        continue;
      }

      if (! isset($node['s'][$seg])) $node['s'][$seg] = ['s' => [], 'w' => null, 'r' => null]; //@phpstan-ignore-line
      $node = &$node['s'][$seg];
    }

    $node['r'] = $r;
    $node['r']['fnx'] = $r['fn'];
  }
  return $rt;
}

function gui_abort_html(int $c = 404): array {
  static $http_codes = null, $code_ar = null;
  if (\is_null($http_codes)) {
    $http_codes = http_status_code();
    $code_ar = array_keys($http_codes);
  }
  $test = \in_array($c, $code_ar);
  $cname = $http_codes[$c] ?? '400 Bad Request';

  return [
    'r_type' => 'html',
    'r_code' => ($test ? $c : 401),
    'r_header' => [
      'Content-Type' => 'text/html',
    ],
    'r_body' => ucwords($cname),
  ];
}

function route_run(array $req = []): ?array {
  $rt = null;

  if (isset($req['r_uri']) && \is_string($req['r_uri'])) {
    global $gv_routecomp;
    $params = [];
    $method = \strtolower($req['r_mtd'] ?? 'get');
    $path = \trim(\parse_url($req['r_uri'] ?? '/', PHP_URL_PATH), '/');
    $segs = $path === '' ? [] : \explode('/', $path);

    if (! isset($gv_routecomp[$method])) return gui_abort_html(405);
    $node = $gv_routecomp[$method];
    
    foreach ($segs as $seg) {
      // static first
      if (isset($node['s'][$seg])) {
        $node = $node['s'][$seg];
        continue;
      }

      // wildcard
      if ($node['w'] !== null) {
        $params[$node['w']['p']] = $seg;
        $node = $node['w'];
        continue;
      }
      return gui_abort_html(404);
    }

    if ($node['r'] === null) return gui_abort_html(404);
    $route = $node['r'];

    foreach ($route['mw'] ?? [] as $mw) {
      if (\is_string($mw) && \function_exists($mw)) {
        if (false === $mw(['req' => $req])) {
          return gui_abort_html(401);
        }
      }
    }

    $rt = ($route['fnx'])(['req' => $req]);
  }

  return $rt;
}

function ascii_table(array $thead, array $tbody, array $tfoot): string {
  $colCount = 0;

  foreach ([$thead, $tbody, $tfoot] as $section) {
    foreach ($section as $row) {
      $count = 0;
      foreach ($row as $cell) {
        $count += $cell['colspan'] ?? 1;
      }
      $colCount = \max($colCount, $count);
    }
  }

  $rows = \array_merge($thead, $tbody, $tfoot);
  $widths = \array_fill(0, $colCount, 0);

  foreach ($rows as $row) {
    $col = 0;
    foreach ($row as $cell) {
      $text = $cell['text'] ?? '';
      $span = $cell['colspan'] ?? 1;

      if ($span === 1) $widths[$col] = \max($widths[$col], \strlen($text));
      $col += $span;
    }
  }

  $line = function() use ($widths) {
    $out = '+';
    foreach ($widths as $w) {
      $out .= \str_repeat('-', $w + 2) . '+';
    }
    return $out . PHP_EOL;
  };

  $renderRow = function($row) use ($widths) {
    $out = '|';
    $col = 0;

    foreach ($row as $cell) {
      $w = 0;
      $text = $cell['text'] ?? '';
      $span = $cell['colspan'] ?? 1;
      for ($i = 0; $i < $span; $i++) {
        $w += $widths[$col + $i] + 3;
      }
      $w -= 1;

      $out .= ' '.\str_pad($text, $w - 1).'|';
      $col += $span;
    }

    return $out.PHP_EOL;
  };

  $out = $line();
  foreach ($thead as $row) {
    $out .= $renderRow($row);
    $out .= $line();
  }

  foreach ($tbody as $row) $out .= $renderRow($row);
  if ($tfoot) {
    $out .= $line();
    foreach ($tfoot as $row) $out .= $renderRow($row);
  }

  $out .= $line().PHP_EOL;
  return $out;
}


$GLOBALS['gv_routecomp'] = route_compile();
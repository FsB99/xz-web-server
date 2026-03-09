<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

global $server_cnf;
$server_cnf['workers'] = cpu_count();

const resp_static = "HTTP/1.1 200 OK\r\n"."Content-Length: 5\r\n"."Connection: keep-alive\r\n\r\n"."hello";
$__clients = $__buffers = $__offsets = [];

function server_start(string $host, int $port, int $workers): void {
  static $os = null, $ev = null, $pcntl = null;
  if (\is_null($pcntl)) {
    global $server_cnf;
    $os = $server_cnf['os'] ?? 'unix';
    $pcntl = $server_cnf['ext_pcntl'] ?? false;
    $ev = $server_cnf['ext_ev'] ?? false;
  }

  echo '[XZ Web Server]';
  echo PHP_EOL.'- OS: '.$os;
  echo PHP_EOL.'- pcntl: '.($pcntl ? 'ok' : '-');
  echo PHP_EOL.'- ev: '.($ev ? 'ok' : '-');
  echo PHP_EOL.'- worker: '.$workers;
  echo PHP_EOL.'Starting Web Server on: http://'.(\in_array($host, ['0.0.0.0', '127.0.0.1']) ? 'localhost' : $host).':'.$port.PHP_EOL.PHP_EOL;

  if ($pcntl && 'unix' === $os && $workers > 1) {
    for ($i = 0; $i < $workers; $i++) {
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
  static $max_header_size = null, $server_idle = null;
  static $watchers = [];
  if (\is_null($max_header_size)) {
    global $server_cnf;
    $max_header_size = $server_cnf['max_header_size'] ?? 8192;
    $server_idle = $server_cnf['idle_second'] ?? 10;
  }

  static $firewall_on = null;
  if (\is_null($firewall_on)) {
    global $server_cnf;
    $module_enabled = $server_cnf['module_enabled'] ?? [];
    if (\in_array('firewall', $module_enabled)) {
      $firewall_on = true;
    }
  }
  
  $loop = EvLoop::defaultLoop();
  $watchers['server'] = $loop->io($server, Ev::READ, function ($w) use ($server, $loop, &$watchers, $max_header_size, &$server_idle, &$firewall_on) {
    while ($client = @stream_socket_accept($server, 0)) {
      stream_set_blocking($client, false);
      $timerWatcher = null;
      $state = [
        'sock'   => $client,
        'buffer' => '',
        'offset' => 0,
        'timer'  => null,
      ];

      $watcher = $loop->io($client, Ev::READ, function ($cw) use ($max_header_size, $watchers, $firewall_on) {
        $state = &$cw->data;
        $sock  = $state['sock'];

        if ($state['timer']) $state['timer']->again();
        $data = @fread($sock, 8192);

        if ('' === $data || false === $data) {
          if ($state['timer']) $state['timer']->stop();

          $cw->stop();
          fclose($sock);
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

          if ($firewall_on) {
            if (firewall_run($req)) {
              drop_connection($sock, 401);
              $cw->stop();
              return;
            }
          }

          if (isset($req['__invalid'])) {
            drop_connection($sock, $req['__invalid']);
            
            if ($state['timer']) $state['timer']->stop();
            $cw->stop();
            unset($watchers[(int)$sock]);
            return;
          }

          handle_req($sock, $req, $state);
        }
      });

      $timerWatcher = $loop->timer(
        $server_idle,
        0,
        function ($tw) use (&$watcher, $client, $watchers) {
          $watcher->stop();
          fclose($client);
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
  static $max_header_size = null;
  if (is_null($max_header_size)) {
    global $server_cnf;
    $max_header_size = $server_cnf['max_header_size'] ?? 8192;
  }

  static $firewall_on = null;
  if (\is_null($firewall_on)) {
    global $server_cnf;
    $module_enabled = $server_cnf['module_enabled'] ?? [];
    if (\in_array('firewall', $module_enabled)) {
      $firewall_on = true;
    }
  }

  while (true) {
    $read = [$server];
    foreach ($__clients as $c) $read[] = $c;
    $write = $except = [];

    if (false === stream_select($read, $write, $except, null)) continue;

    foreach ($read as $sock) {
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
        fclose($sock);
        unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
        continue;
      }

      $__buffers[$id] .= $data;

      if (\strlen($__buffers[$id]) > $max_header_size) {
        drop_connection($sock, 413);
        fclose($sock);
        unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
        continue;
      }

      while (true) {
        $req = parse_request($__buffers[$id], $__offsets[$id]);
        if (\is_null($req)) break;

        if ($firewall_on) {
          if (firewall_run($req)) {
            drop_connection($sock, 401);
            if (\is_resource($sock)) fclose($sock);
            unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
            break;
          }
        }

        if (isset($req['__invalid'])) {
          drop_connection($sock, $req['__invalid']);
          fclose($sock);
          unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
          break;
        }

        handle_req($sock, $req, ['timer' => null]);

        if (isset($req['r_close']) && $req['r_close']) {
          fclose($sock);
          unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
          break;
        }
      }
    }
  }
}

function parse_request(string &$buffer, int &$offset): ?array {
  static $max_header_size = null, $max_body_size = null, $max_uri_length = null;
  if (\is_null($max_header_size)) {
    global $server_cnf;
    $max_header_size = $server_cnf['max_header_size'];
    $max_body_size   = $server_cnf['max_body_size'];
    $max_uri_length  = $server_cnf['max_uri_length'];
  }

  $len = \strlen($buffer);
  $headers = $cookies = $get = $post = $files = [];
  $header_end = \strpos($buffer, "\r\n\r\n", $offset);

  if (false === $header_end) {
    if ($len > $max_header_size) return ['__invalid' => 413];
    return null;
  }

  $header_end += 4;

  if ($header_end > $max_header_size) return ['__invalid' => 413];

  // request line
  $line_end = \strpos($buffer, "\r\n", $offset);
  if (false === $line_end) return ['__invalid' => 400];

  $sp1 = \strpos($buffer, ' ', $offset);
  if (false === $sp1) return ['__invalid' => 400];

  $sp2 = \strpos($buffer, ' ', $sp1 + 1);
  if (false === $sp2 || $sp2 > $line_end) return ['__invalid' => 400];

  $method = \strtolower(\substr($buffer, $offset, $sp1 - $offset));
  if (! \in_array($method, ['get', 'post', 'head'], true)) return ['__invalid' => 405];

  $uri = \substr($buffer, $sp1 + 1, $sp2 - $sp1 - 1);
  if (\strlen($uri) > $max_uri_length || \str_contains($uri, "\0")) return ['__invalid' => 414];

  $http = \substr($buffer, $sp2 + 1, $line_end - $sp2 - 1);
  if (! \in_array($http, ['HTTP/1.1', 'HTTP/1.0'], true)) return ['__invalid' => 400];

  $qpos = \strpos($uri, '?');
  $path = (false === $qpos) ? $uri : \substr($uri, 0, $qpos);
  $query_str = (false === $qpos) ? '' : \substr($uri, $qpos + 1);
  $content_length = 0;
  $content_length_seen = $transfer_encoding_seen = false;
  $h_start = $line_end + 2;

  while ($h_start < $header_end - 2) {
    $h_end = \strpos($buffer, "\r\n", $h_start);
    if (false === $h_end) break;

    $colon = \strpos($buffer, ':', $h_start);
    
    if (false !== $colon && $colon < $h_end) {
      $raw_key = \substr($buffer, $h_start, $colon - $h_start);
      $key = \strtolower(\trim($raw_key));
      $val = \trim(\substr($buffer, $colon + 1, $h_end - $colon - 1));

      if (!\preg_match('#^[a-z0-9\-]+$#', $key)) return ['__invalid' => 400];
      if (\str_contains($val, "\r") || \str_contains($val, "\n")) return ['__invalid' => 400];
      $headers[$key] = $val;
      if ('transfer-encoding' === $key) $transfer_encoding_seen = true;
      if ($key === 'content-length') {
        if (!\ctype_digit($val)) return ['__invalid' => 400];

        if ($content_length_seen) {
          if ((int)$val !== $content_length) return ['__invalid' => 400];

          return ['__invalid' => 400];
        }

        $content_length_seen = true;
        $content_length = (int)$val;

        if ($content_length < 0 || $content_length > $max_body_size) return ['__invalid' => 413];
      }

      if ('cookie' === $key) parse_kv(\str_replace('; ', '&', $val), $cookies);
    }

    $h_start = $h_end + 2;
  }

  if ($transfer_encoding_seen) return ['__invalid' => 501];
  if ($transfer_encoding_seen && $content_length_seen) return ['__invalid' => 400];
  if ('HTTP/1.1' === $http && ! isset($headers['host'])) return ['__invalid' => 400];
  if (isset($headers['transfer-encoding'])) return ['__invalid' => 501];

  $total = $header_end + $content_length;
  if ($len < $total) return null;

  $body = $content_length > 0 ? \substr($buffer, $header_end, $content_length) : '';

  if ('' !== $query_str) parse_kv($query_str, $get);
  if ('post' === $method && $content_length > 0) {
    if (isset($headers['content-type']) && \str_contains($headers['content-type'], 'application/x-www-form-urlencoded')) parse_kv($body, $post);
  }

  $buffer = \substr($buffer, $total);
  $offset = 0;

  $rt = [
    'r_ver' => $http,
    'r_head' => $headers,
    'r_ip' => null,
    'r_cookie' => $cookies,
    'r_uri' => $uri,
    'r_path' => $path,
    'r_mtd' => $method,
    'r_files' => $files,
    'r_get' => $get,
    'r_post' => $post,
    'r_body' => $body,
    'r_close'  => isset($headers['connection']) && \strtolower($headers['connection']) === 'close',
    'r_expect_continue' => isset($headers['expect']) && \strtolower($headers['expect']) === '100-continue'
  ];
  
  return $rt;
}

function parse_kv(string $str, array &$out): void {
  $len = \strlen($str);
  $key = $val = '';
  $reading_key = true;

  for ($i = 0; $i < $len; $i++) {
    $ch = $str[$i];

    if ($reading_key) {
      if ('=' === $ch) {
        $reading_key = false;
      } elseif ('&' === $ch) {
        $out[$key] = '';
        $key = '';
      } else {
        $key .= $ch;
      }

    } else {
      if ('&' === $ch) {
        $out[$key] = $val;
        $key = '';
        $val = '';
        $reading_key = true;
      } else {
        $val .= $ch;
      }
    }
  }

  if ('' !== $key) $out[$key] = $val;
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
  static $status = null;
  if (\is_null($status)) {
    $status = http_status_code();
  }
  $close = false;

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
    fclose($sock);
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
  fclose($sock);
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
    if ($out && \is_string($out) && preg_match('/NumberOfCores=(\d+)/', $out, $m)) { 
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

      if (! isset($node['s'][$seg])) $node['s'][$seg] = ['s' => [], 'w' => null, 'r' => null];
      $node = &$node['s'][$seg];
    }

    $node['r'] = $r;
    $node['r']['fnx'] = $r['fn'];
  }
  return $rt;
}

function gui_abort_html(int $c = 404) {
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

$GLOBALS['gv_routecomp'] = route_compile();
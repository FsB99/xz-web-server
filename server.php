<?php
declare(strict_types=1);
set_time_limit(0);
error_reporting(E_ALL);

$GLOBALS['server_cnf'] = [
  'host' => '0.0.0.0',
  'port' => 8080,
  'workers' => cpu_count(),
  'max_header_size' => 8192,
  'max_body_size' => 1048576 * 2, // 1Mb base
  'max_uri_length' => 2048,
  'idle_second' => 10,
  'os' => (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' ? 'win' : 'unix'),
  'ext_ev' => extension_loaded('ev'),
  'ext_pcntl' => function_exists('pcntl_fork'),
];
CONST resp_static = "HTTP/1.1 200 OK\r\n"."Content-Length: 5\r\n"."Connection: keep-alive\r\n\r\n"."hello";

/** @var array<int, resource> */
$__clients = [];

/** @var array<int, string> */
$__buffers = [];

/** @var array<int, int> */
$__offsets = [];

function server_start(string $host, int $port, int $workers): void {
  static $pcntl = null; $os = null;

  if (\is_null($pcntl)) {
    global $server_cnf;
    $pcntl = $server_cnf['ext_pcntl'] ?? false;
    $os = $server_cnf['os'] ?? 'unix';
  }

  echo '[XZ Web Server]'.PHP_EOL;
  echo PHP_EOL.'- pcntl: '.($pcntl ? 'ok' : 'none');
  echo PHP_EOL.'- os: '.$os;
  echo PHP_EOL.'- Listening on: '.$host.':'.$port.' | '.$workers.PHP_EOL;

  if ($pcntl && 'unix' === $os && $workers > 1) {
    for ($i = 0; $i < $workers; $i++) {
      $pid = pcntl_fork();
      if ($pid === 0) {
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

  if (! $server) {
    die("Server error: {$errstr}\n");
  }

  stream_set_blocking($server, false);
  echo "- PID ".getmypid();

  if ($ev) {
    loop_ev($server);
  } else {
    loop_select($server);
  }
}

function loop_ev($server): void {
  static $max_header_size = null;

  if (\is_null($max_header_size)) {
    global $server_cnf;
    $max_header_size = $server_cnf['max_header_size'] ?? 8192;
  }

  $loop = EvLoop::defaultLoop();
  $loop->io($server, Ev::READ, function($w) use ($loop, $max_header_size) {
    global $__clients, $__buffers, $__offsets;
    $client = stream_socket_accept($w->fd, 0);
    if (!$client) return;

    stream_set_blocking($client, false);
    $id = (int)$client;
    $__clients[$id] = $client;
    $__buffers[$id] = '';
    $__offsets[$id] = 0;

    $loop->io($client, Ev::READ, function($cw) use ($__clients, $__buffers, $__offsets, $max_header_size) {
      $sock = $cw->fd;
      $id = (int)$sock;
      $data = fread($sock, 8192);

      if (strlen($__buffers[$id]) > $max_header_size) {
        drop_connection($sock, 413);
        return;
      }

      if ($data === '' || $data === false) {
        fclose($sock);
        unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
        return;
      }

      $__buffers[$id] .= $data;

      while (true) {
        $req = try_parse_request_fast($__buffers[$id], $__offsets[$id]);
        if ($req === null) break;

        if (isset($req['__invalid'])) {
          drop_connection($sock, $req['__invalid']);
          unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
          break;
        }

        handle_fast($sock, $req);
      }
    });
  });

  $loop->run();
}

function loop_select($server): void {
  global $__clients, $__buffers, $__offsets;
  static $max_header_size = null;

  if (\is_null($max_header_size)) {
    global $server_cnf;
    $max_header_size = $server_cnf['max_header_size'] ?? 8192;
  }

  while (true) {
    $read = [$server];
    foreach ($__clients as $c) $read[] = $c;
    $write = $except = [];

    if (stream_select($read, $write, $except, null) === false) {
      continue;
    }

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

      } else {
        $id = (int)$sock;
        $data = fread($sock, 8192);

        if (strlen($__buffers[$id]) > $max_header_size) {
          drop_connection($sock, 413);
          continue;
        }

        if ($data === '' || $data === false) {
          fclose($sock);
          unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
          continue;
        }

        $__buffers[$id] .= $data;

        while (true) {
          $req = try_parse_request_fast($__buffers[$id], $__offsets[$id]);
          if ($req === null) break;

          if (isset($req['__invalid'])) {
            drop_connection($sock, $req['__invalid']);
            unset($__clients[$id], $__buffers[$id], $__offsets[$id]);
            break;
          }

          handle_fast($sock, $req);
        }
      }
    }
  }
}

function try_parse_request_fast(string &$buffer, int &$offset): ?array {
  static $max_header_size = null, $max_body_size = null, $max_uri_length = null;

  if (\is_null($max_header_size)) {
    global $server_cnf;
    $max_header_size = $server_cnf['max_header_size'] ?? 8192;
    $max_body_size = $server_cnf['max_body_size'] ?? 1048576;
    $max_uri_length = $server_cnf['max_uri_length'] ?? 2048;
  }

  $len = strlen($buffer);
  $headerEnd = -1;

  for ($i = max(3, $offset); $i < $len; $i++) {
    if ($buffer[$i-3] === "\r" && $buffer[$i-2] === "\n" && $buffer[$i-1] === "\r" && $buffer[$i]   === "\n") {
      $headerEnd = $i + 1;
      break;
    }
  }

  if ($headerEnd === -1) {
    $offset = $len;
    return null;
  }

  if ($headerEnd > $max_header_size) {
    return ['__invalid' => 413];
  }

  // method + uri
  $sp1 = strpos($buffer, ' ');
  $headerStr = substr($buffer, 0, $headerEnd);
  $offset = $headerEnd;
  if ($sp1 === false) return null;

  $sp2 = strpos($buffer, ' ', $sp1 + 1);
  $httpEnd = strpos($buffer, "\r\n");
  $httpLine = substr($buffer, $sp2 + 1, $httpEnd - $sp2 - 1);

  if ($httpLine !== 'HTTP/1.1' && $httpLine !== 'HTTP/1.0') {
    return ['__invalid' => 400];
  }

  if ($sp2 === false) return null;

  $method = substr($buffer, 0, $sp1);
  $uri = substr($buffer, $sp1 + 1, $sp2 - $sp1 - 1);
  $contentLength = 0;

  if ($method !== 'GET' && $method !== 'POST' && $method !== 'HEAD') {
    return ['__invalid' => 405];
  }

  if (strlen($uri) > $max_uri_length) {
    return ['__invalid' => 414];
  }

  if (str_contains($uri, "\0") || str_contains($uri, "..")) {
    return ['__invalid' => 400];
  }

  $path = substr($headerStr, $sp1 + 1, $sp2 - $sp1 - 1);
  $query = [];

  if (($qpos = strpos($path, '?')) !== false) {
    $path = substr($path, 0, $qpos);
    parse_kv(substr($path, $qpos + 1), $query);
  }

  $clPos = stripos($buffer, "\r\nContent-Length:");
  if ($clPos !== false && $clPos < $headerEnd) {
    $numStart = $clPos + 17;
    $numEnd = strpos($buffer, "\r\n", $numStart);
    if ($numEnd !== false) {
      $contentLength = (int)substr($buffer, $numStart, $numEnd - $numStart);
    }
  }

  $total = $headerEnd + $contentLength;

  if ($len < $total) {
    return null;
  }

  if ($contentLength < 0 || $contentLength > $max_body_size) {
    return ['__invalid' => 413];
  }

  $body = $contentLength > 0
    ? substr($buffer, $headerEnd, $contentLength)
    : '';

  $offset = $total;

  if ($offset > 8192) {
    $buffer = substr($buffer, $offset);
    $offset = 0;
  }

  // headers
  $headers = [];
  $lines = explode("\r\n", $headerStr);

  foreach ($lines as $line) {
    $colon = strpos($line, ':');
    if ($colon === false) continue;

    $key = strtolower(trim(substr($line, 0, $colon)));
    $val = trim(substr($line, $colon + 1));
    $headers[$key] = $val;
  }

  return [
    'm' => $method,
    'u' => $uri,
    'q' => $query,
    'h' => $headers,
    'b' => $body,
  ];
}

function parse_kv(string $str, array &$out): void {
  $len = strlen($str);
  $key = $val = '';
  $readingKey = true;

  for ($i = 0; $i < $len; $i++) {
    $ch = $str[$i];

    if ($readingKey) {
      if ($ch === '=') {
        $readingKey = false;
      } elseif ($ch === '&') {
        $out[$key] = '';
        $key = '';
      } else {
        $key .= $ch;
      }

    } else {
      if ($ch === '&') {
        $out[$key] = $val;
        $key = '';
        $val = '';
        $readingKey = true;
      } else {
        $val .= $ch;
      }
    }
  }

  if ($key !== '') {
    $out[$key] = $val;
  }
}

function handle_fast($sock, array $req): void {
  if ($req['u'] === '/') {
    fwrite($sock, resp_static);
    return;
  }

  // fallback 
  $body = "Path: ".$req['u'];
  $len = strlen($body);

  $out ="HTTP/1.1 200 OK\r\n"."Content-Length: {$len}\r\n"."Connection: keep-alive\r\n\r\n".$body;
  fwrite($sock, $out);
}

function drop_connection($sock, int $code): void {
  $msg = match ($code) {
    400 => "400 Bad Request",
    405 => "405 Method Not Allowed",
    408 => "408 Request Timeout",
    413 => "413 Payload Too Large",
    414 => "414 URI Too Long",
    default => "400 Bad Request"
  };
  $body = $msg;
  $out = "HTTP/1.1 {$msg}\r\n"."Content-Length: ".strlen($body)."\r\n"."Connection: close\r\n\r\n".$body;
  fwrite($sock, $out);
  fclose($sock);
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

if (PHP_SAPI === 'cli') {
  server_start($server_cnf['host'], $server_cnf['port'], $server_cnf['workers']);
}
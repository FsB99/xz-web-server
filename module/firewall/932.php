<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

$powershell_commands_data = firewall_readfile('./module/firewall/windows_powershell_commands.data');
$rx_932120 = '~(?:'.\implode('|', \array_map(
  fn($v) => \preg_quote($v, '~'),
  $powershell_commands_data
)).')~i';

return [
  [
    'id' => 932120,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['rce', 'powershell'],
    'capec' => [1000, 152, 248, 88],
    'score' => 5,
    'msg' => 'Remote Command Execution: Windows PowerShell Command Found',
    'rule' => [
      ['w' => ['cookie', 'cookie_names', 'args', 'args_names'], 'rx' => $rx_932120],
    ],
  ],
  [
    'id' => 932125,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['rce', 'powershell'],
    'capec' => [1000, 152, 248, 88],
    'score' => 5,
    'msg' => 'Remote Command Execution: Windows Powershell Alias Command Injection',
    'rule' => [
      ['w' => ['cookie', 'cookie_names', 'args', 'args_names'], 'rx' => '~(?i)(?:[\n\r;`\{]|\|\|?|&&?)[\s\x0b]*[\s\x0b"\'\(,@]*(?:["\'\.-9A-Z_a-z]+/|(?:["\'\x5c\^]*[0-9A-Z_a-z]["\'x5c\^]*:.*|[ "\'\.-9A-Z\x5c\^_a-z]*)\x5c)?["\^]*(?:(?:a["\^]*(?:c|s["\^]*n["\^]*p)|e["\^]*(?:b["\^]*p|p["\^]*(?:a["\^]*l|c["\^]*s["\^]*v|s["\^]*n)|[tx]["\^]*s["\^]*n)|f["\^]*(?:[cltw]|o["\^]*r["\^]*e["\^]*a["\^]*c["\^]*h)|i["\^]*(?:[cr]["\^]*m|e["\^]*x|h["\^]*y|i|p["\^]*(?:a["\^]*l|c["\^]*s["\^]*v|m["\^]*o|s["\^]*n)|s["\^]*e|w["\^]*(?:m["\^]*i|r))|m["\^]*(?:[dpv]|o["\^]*u["\^]*n["\^]*t)|o["\^]*g["\^]*v|p["\^]*(?:o["\^]*p|u["\^]*s["\^]*h)["\^]*d|t["\^]*r["\^]*c["\^]*m|w["\^]*j["\^]*b)["\^]*[\s\x0b,\./;<>].*|c["\^]*(?:(?:(?:d|h["\^]*d["\^]*i["\^]*r|v["\^]*p["\^]*a)["\^]*|p["\^]*(?:[ip]["\^]*)?)[\s\x0b,\./;<>].*|l["\^]*(?:(?:[cipv]|h["\^]*y)["\^]*[\s\x0b,\./;<>].*|s)|n["\^]*s["\^]*n)|d["\^]*(?:(?:b["\^]*p|e["\^]*l|i["\^]*(?:f["\^]*f|r))["\^]*[\s\x0b,\./;<>].*|n["\^]*s["\^]*n)|g["\^]*(?:(?:(?:(?:a["\^]*)?l|b["\^]*p|d["\^]*r|h["\^]*y|(?:w["\^]*m["\^]*)?i|j["\^]*b|[uv])["\^]*|c["\^]*(?:[ims]["\^]*)?|m["\^]*(?:o["\^]*)?|s["\^]*(?:n["\^]*(?:p["\^]*)?|v["\^]*))[\s\x0b,\./;<>].*|e["\^]*r["\^]*r|p["\^]*(?:(?:s["\^]*)?[\s\x0b,\./;<>].*|v))|l["\^]*s|n["\^]*(?:(?:a["\^]*l|d["\^]*r|[iv]|m["\^]*o|s["\^]*n)["\^]*[\s\x0b,\./;<>].*|p["\^]*s["\^]*s["\^]*c)|r["\^]*(?:(?:(?:(?:b["\^]*)?p|e["\^]*n|(?:w["\^]*m["\^]*)?i|j["\^]*b|n["\^]*[ip])["\^]*|d["\^]*(?:r["\^]*)?|m["\^]*(?:(?:d["\^]*i["\^]*r|o)["\^]*)?|s["\^]*n["\^]*(?:p["\^]*)?|v["\^]*(?:p["\^]*a["\^]*)?)[\s\x0b,\./;<>].*|c["\^]*(?:j["\^]*b["\^]*[\s\x0b,\./;<>].*|s["\^]*n)|u["\^]*j["\^]*b)|s["\^]*(?:(?:(?:a["\^]*(?:j["\^]*b|l|p["\^]*s|s["\^]*v)|b["\^]*p|[cv]|w["\^]*m["\^]*i)["\^]*|l["\^]*(?:s["\^]*)?|p["\^]*(?:(?:j["\^]*b|p["\^]*s|s["\^]*v)["\^]*)?)[\s\x0b,\./;<>].*|h["\^]*c["\^]*m|u["\^]*j["\^]*b))(?:\.["\^]*[0-9A-Z_a-z]+)?\b~'],
    ],
  ],
  [
    'id' => 932130,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['rce', 'shell', 'unix'],
    'capec' => [1000, 152, 248, 88],
    'score' => 5,
    'msg' => 'Remote Command Execution: Unix Shell Expression Found',
    'rule' => [
      ['w' => ['cookie', 'cookie_names', 'args', 'args_names'], 'rx' => '~\$(?:\((?:[^\)]+|\([^\)]+\))\)|\{[^\}]+\}|\[[^\]]*\])|[<>]\([^\)]+\)|/[0-9A-Z_a-z]*\[[^\]]+\]~'],
    ],
  ],
  [
    'id' => 932140,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['rce', 'shell', 'windows'],
    'capec' => [1000, 152, 248, 88],
    'score' => 5,
    'msg' => 'Remote Command Execution: Windows FOR/IF Command Found',
    'rule' => [
      ['w' => ['cookie', 'cookie_names', 'args', 'args_names'], 'rx' => '~\b(?:for(?:/[dflr].*)? %+[^ ]+ in\(.*\)[\s\x0b]?do|if(?:/i)?(?: not)?(?: (?:e(?:xist|rrorlevel)|defined|cmdextversion)\b|[ \(].*(?:\b(?:g(?:eq|tr)|equ|neq|l(?:eq|ss))\b|==)))~'],
    ],
  ],
  [
    'id' => 932270,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['rce', 'shell', 'unix'],
    'capec' => [1000, 152, 248, 88],
    'score' => 5,
    'msg' => 'Remote Command Execution: Unix Shell Expression Found',
    'rule' => [
      ['w' => ['cookie', 'cookie_names', 'args', 'args_names'], 'rx' => '~[\+\-](?:$|[0-9]+)~'],
    ],
  ],
  [
    'id' => 932280,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['rce', 'shell', 'unix'],
    'capec' => [1000, 152, 248, 88],
    'score' => 5,
    'msg' => 'Remote Command Execution: Brace Expansion Found',
    'rule' => [
      ['w' => ['cookie', 'cookie_names', 'args', 'args_names'], 'rx' => '~\{[0-9A-Z_a-z]*,[,\-0-9A-Z_a-z]*\}~'],
    ],
  ],
  [
    'id' => 932330,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['rce', 'shell', 'unix'],
    'capec' => [1000, 152, 248, 88],
    'score' => 5,
    'msg' => 'Remote Command Execution: Unix shell history invocation',
    'rule' => [
      ['w' => ['cookie', 'cookie_names', 'args', 'args_names'], 'rx' => '~!-\d~'],
    ],
  ],
];
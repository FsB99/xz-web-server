<?php
// XZ Web Server by Fsb
declare(strict_types=1);

// credited to : https://github.com/coreruleset/coreruleset
// Since CRS used regex and SecLang, this will be the re-implementasion for lightweight and performance wise for PHP

// $struct_scorebase = [
//   5 => 'critical',
//   4 => 'error',
//   3 => 'warning',
//   2 => 'notice',
// ];

// $struct_scan_where = [
//   'REQUEST_METHOD' => 'GET/POST/etc',
//   'ARGS' => 'request parameters',
//   'ARGS_NAMES' => 'parameter names',
//   'REQUEST_HEADERS' => 'headers',
//   'REQUEST_FILENAME' => 'URL path',
//   'REQUEST_COOKIES' => 'cookie',
// ];

// https://capec.mitre.org/data/definitions/272.html

$GLOBALS['crs_rules'] = [
  [
    'id' => 920170,
    'phase' => 1,
    'rule' => [
      ['w' => 'method', 't' => 'in', 'v' => ['GET','HEAD']],
      ['w' => 'header', 'wpr' => 'Content-Length', 'eq' => '0'],
    ],
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 5,
  ],
  [
    'id' => 920171,
    'phase' => 1,
    'rule' => [
      ['w' => 'method', 't' => 'in', 'v' => ['GET','HEAD']],
      ['w' => 'header', 'wpr' => 'Content-Length', 'eq' => '0'],
    ],
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 5,
  ],
  [
    'id' => 920181,
    'phase' => 1,
    'rule' => [
      ['w' => 'header', 'wpr' => 'Transfer-Encoding', 'eq' => '0'],
    ],
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 4,
  ],
  [
    'id' => 920190,
    'phase' => 1,
    'rule' => [
      ['w' => 'header', 'wpr' => 'Range', 'rx' => '~(\d+)-(\d+)~'],
    ],
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 5,
  ],
  [
    'id' => 920660,
    'phase' => 1,
    'rule' => [
      ['w' => 'header', 'wpr' => 'Request-Range', 'eq' => '0'],
    ],
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 4,
  ],
  [
    'id' => 920210,
    'phase' => 1,
    'rule' => [
      ['w' => 'header', 'wpr' => 'Connection', 'rx' => '~\b(?:keep-alive|close),\s?(?:keep-alive|close)\b~'],
    ],
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 4,
  ]
];
<?php
// XZ Web Server by Fsb
declare(strict_types=1);

return [
  [
    'id' => 920170,
    'phase' => 1,
    'rule' => [
      ['w' => ['method'], 'in' => ['GET', 'HEAD']],
      ['w' => 'header', 'wpr' => 'Content-Length', 'eq' => '0'],
    ],
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 5,
  ],
  // [
  //   'id' => 920181,
  //   'phase' => 1,
  //   'rule' => [
  //     ['w' => ['header'], 'wpr' => 'Transfer-Encoding', 'eq' => '0'],
  //   ],
  //   'pl' => 1,
  //   'atk_cat' => ['protocol'],
  //   'capec' => [1000, 210, 272],
  //   'score' => 4,
  // ],
  // [
  //   'id' => 920190,
  //   'phase' => 1,
  //   'rule' => [
  //     ['w' => ['header'], 'wpr' => 'Range', 'rx' => '~(\d+)-(\d+)~'],
  //   ],
  //   'pl' => 1,
  //   'atk_cat' => ['protocol'],
  //   'capec' => [1000, 210, 272],
  //   'score' => 5,
  // ],
  [
    'id' => 920660,
    'phase' => 1,
    'rule' => [
      ['w' => ['header'], 'wpr' => 'Request-Range', 'eq' => '0'],
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
      ['w' => ['header'], 'wpr' => 'Connection', 'rx' => '~\b(?:keep-alive|close),\s?(?:keep-alive|close)\b~'],
    ],
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 4,
  ],
  [
    'id' => 920260,
    'phase' => 2,
    'rule' => [
      ['w' => ['body', 'uri'], 'wpr' => '', 'rx' => '~(?i)%uff[0-9a-f]{2}~'],
    ],
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 255, 153, 267, 72],
    'score' => 4,
  ],
  [
    'id' => 920270,
    'phase' => 2,
    'rule' => [
      ['w' => ['uri'], 'wpr' => '', 'maxl' => 255],
    ],
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 5,
  ],
];
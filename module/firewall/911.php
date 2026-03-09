<?php
// XZ Web Server by Fsb
declare(strict_types=1);

return [
  [
    'id' => 911100,
    'phase' => 1,
    'rule' => [
      ['w' => ['method'], 'in' => ['GET', 'HEAD', 'POST'], 'not' => true],
    ],
    'pl' => 1,
    'atk_cat' => ['generic'],
    'capec' => [1000, 210, 272, 220, 274],
    'score' => 5,
  ],
];
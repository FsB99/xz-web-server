<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

return [
  [
    'id' => 911100,
    'phase' => 1,
    'pl' => 1,
    'atk_cat' => ['generic'],
    'capec' => [1000, 210, 272, 220, 274],
    'score' => 5,
    'msg' => 'Method is not allowed by policy',
    'rule' => [
      ['w' => ['method'], 'in' => ['GET', 'HEAD', 'POST'], 'not' => true],
    ],
  ],
];
<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

$scanners_user_agents_data = firewall_readfile('./module/firewall/scanners_user_agents.data');
$rx_913100 = '~(?:'.\implode('|', \array_map(
  fn($v) => \preg_quote($v, '~'),
  $scanners_user_agents_data
)).')~i';

return [
  [
    'id' => 913100,
    'phase' => 1,
    'pl' => 1,
    'atk_cat' => ['reputation_scanner'],
    'capec' => [1000, 118, 224, 541, 310],
    'score' => 5,
    'msg' => 'Found User-Agent associated with security scanner',
    'rule' => [
      ['w' => ['header'], 'wpr' => 'User-Agent', 'rx' => $rx_913100],
    ],
  ],
];
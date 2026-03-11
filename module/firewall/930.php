<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

$lfi_os_files = firewall_readfile('./module/firewall/lfi_os_files.data');
$rx_930120 = '~('.implode('|', $lfi_os_files).')~i';

$restricted_files = firewall_readfile('./module/firewall/restricted_files.data');
$rx_930130 = '~('.implode('|', $restricted_files).')~i';

// $ai_critical_artifacts = firewall_readfile('./module/firewall/ai_critical_artifacts.data');
// $rx_930140 = '~('.implode('|', $ai_critical_artifacts).')~i';

return [
  // [
  //   'id' => 930100,
  //   'phase' => 2,
  //   'pl' => 1,
  //   'atk_cat' => ['lfi'],
  //   'capec' => [1000, 255, 153, 126],
  //   'score' => 5,
  //   'msg' => 'Path Traversal Attack (/../) or (/.../)',
  //   'rule' => [
  //     ['w' => ['uri', 'get', 'header', 'files'], 'rx' => '~(?i)(?:[/\x5c]|%(?:2(?:f|5(?:2f|5c|c(?:1%259c|0%25af))|%46)|5c|c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|(?:bg%q|(?:e|f(?:8%8)?0%8)0%80%a)f|u(?:221[56]|EFC8|F025|002f)|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|1u)|0x(?:2f|5c))(?:\.(?:%0[01]|\?)?|\?\.?|%(?:2(?:(?:5(?:2|c0%25a))?e|%45)|c0(?:\.|%[256aef]e)|u(?:(?:ff0|002)e|2024)|%32(?:%(?:%6|4)5|E)|(?:e|f(?:(?:8|c%80)%8)?0%8)0%80%ae)|0x2e){2,3}(?:[/\x5c]|%(?:2(?:f|5(?:2f|5c|c(?:1%259c|0%25af))|%46)|5c|c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|(?:bg%q|(?:e|f(?:8%8)?0%8)0%80%a)f|u(?:221[56]|EFC8|F025|002f)|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|1u)|0x(?:2f|5c))~'],
  //   ],
  // ],
  // [
  //   'id' => 930110,
  //   'phase' => 2,
  //   'pl' => 1,
  //   'atk_cat' => ['lfi'],
  //   'capec' => [1000, 255, 153, 126],
  //   'score' => 5,
  //   'msg' => 'Path Traversal Attack (/../) or (/.../)',
  //   'rule' => [
  //     ['w' => ['uri', 'get', 'header', 'files'], 'rx' => '~(?:^|[\/;\\\\])\.{2,3}(?:[\/;\\\\]|$)~'],
  //   ],
  // ],
  // [
  //   'id' => 930120,
  //   'phase' => 2,
  //   'pl' => 1,
  //   'atk_cat' => ['lfi'],
  //   'capec' => [1000, 255, 153, 126],
  //   'score' => 5,
  //   'msg' => 'OS File Access Attempt',
  //   'rule' => [
  //     ['w' => ['cookie', 'get', 'header'], 'rx' => $rx_930120],
  //   ],
  // ],
  // [
  //   'id' => 930130,
  //   'phase' => 1,
  //   'pl' => 1,
  //   'atk_cat' => ['lfi'],
  //   'capec' => [1000, 255, 153, 126],
  //   'score' => 5,
  //   'msg' => 'Restricted File Access Attempt',
  //   'rule' => [
  //     ['w' => ['files'], 'rx' => $rx_930130],
  //   ],
  // ],
  // [
  //   'id' => 930140,
  //   'phase' => 1,
  //   'pl' => 1,
  //   'atk_cat' => ['lfi'],
  //   'capec' => [1000, 255, 153, 126],
  //   'score' => 5,
  //   'msg' => 'Restricted File Access Attempt: AI Coding Assistant Artifact',
  //   'rule' => [
  //     ['w' => ['files_name'], 'rx' => $rx_930140],
  //   ],
  // ],
];
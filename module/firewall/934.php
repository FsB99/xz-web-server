<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

$ssrf = firewall_readfile('./module/firewall/ssrf.data');
$rx_934110 = '~(?:'.\implode('|', array_map(
  fn($v) => preg_quote($v, '~'),
  $ssrf
)).')~i';

$ssrf_no_scheme = firewall_readfile('./module/firewall/ssrf_no_scheme.data');
$rx_934190 = '~(?:'.\implode('|', array_map(
  fn($v) => preg_quote($v, '~'),
  $ssrf_no_scheme
)).')~i';

return [
  [
    'id' => 934110,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['injection_generic', 'ssrf'],
    'capec' => [1000, 152, 242],
    'score' => 5,
    'msg' => 'Possible Server Side Request Forgery (SSRF) Attack: Cloud provider metadata URL in Parameter',
    'rule' => [
      ['w' => ['cookie', 'args', 'files'], 'rx' => $rx_934110],
    ],
  ],
  [
    'id' => 934190,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['injection_generic', 'ssrf'],
    'capec' => [1000, 152, 242],
    'score' => 5,
    'msg' => 'Possible Server Side Request Forgery (SSRF) Attack: Cloud provider metadata URL in Parameter',
    'rule' => [
      ['w' => ['cookie', 'args', 'files'], 'rx' => $rx_934190],
    ],
  ],
  [
    'id' => 934130,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['injection_generic', 'rce'],
    'capec' => [1000, 152, 242],
    'score' => 5,
    'msg' => 'JavaScript Prototype Pollution',
    'rule' => [
      ['w' => ['cookie', 'args'], 'rx' => '~__proto__|constructor[\s\x0b]*(?:\.|\]?\[)[\s\x0b]*prototype~'],
    ],
  ],
  [
    'id' => 934170,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['injection_generic', 'ssrf'],
    'capec' => [1000, 152, 242],
    'score' => 5,
    'msg' => 'PHP data scheme attack',
    'rule' => [
      ['w' => ['cookie', 'args', 'files'], 'rx' => '~^data:(?:(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)/(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)|\*)(?:[\s\x0b]*;[\s\x0b]*(?:charset[\s\x0b]*=[\s\x0b]*\"?(?:iso-8859-15?|utf-8|windows-1252)\b\"?|(?:[^\s\x0b-\"\(\),/:-\?\[-\]c\{\}]|c(?:[^!\"\(\),/:-\?\[-\]h\{\}]|h(?:[^!\"\(\),/:-\?\[-\]a\{\}]|a(?:[^!\"\(\),/:-\?\[-\]r\{\}]|r(?:[^!\"\(\),/:-\?\[-\]s\{\}]|s(?:[^!\"\(\),/:-\?\[-\]e\{\}]|e[^!\"\(\),/:-\?\[-\]t\{\}]))))))[^!\"\(\),/:-\?\[-\]\{\}]*[\s\x0b]*=[\s\x0b]*[^!\(\),/:-\?\[-\]\{\}]+);?)*(?:[\s\x0b]*,[\s\x0b]*(?:(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)/(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)|\*)(?:[\s\x0b]*;[\s\x0b]*(?:charset[\s\x0b]*=[\s\x0b]*\"?(?:iso-8859-15?|utf-8|windows-1252)\b\"?|(?:[^\s\x0b-\"\(\),/:-\?\[-\]c\{\}]|c(?:[^!\"\(\),/:-\?\[-\]h\{\}]|h(?:[^!\"\(\),/:-\?\[-\]a\{\}]|a(?:[^!\"\(\),/:-\?\[-\]r\{\}]|r(?:[^!\"\(\),/:-\?\[-\]s\{\}]|s(?:[^!\"\(\),/:-\?\[-\]e\{\}]|e[^!\"\(\),/:-\?\[-\]t\{\}]))))))[^!\"\(\),/:-\?\[-\]\{\}]*[\s\x0b]*=[\s\x0b]*[^!\(\),/:-\?\[-\]\{\}]+);?)*)*~'],
    ],
  ],
  [
    'id' => 934101,
    'phase' => 2,
    'pl' => 2,
    'atk_cat' => ['injection_generic', 'rce'],
    'capec' => [1000, 152, 242],
    'score' => 5,
    'msg' => 'Node.js Injection Attack 2/2',
    'rule' => [
      ['w' => ['cookie', 'args', 'files'], 'rx' => '~(?:close|exists|fork|(?:ope|spaw)n|re(?:ad|quire)|w(?:atch|rite))[\s\x0b]*\(~'],
    ],
  ],
  [
    'id' => 934120,
    'phase' => 2,
    'pl' => 2,
    'atk_cat' => ['injection_generic', 'ssrf'],
    'capec' => [1000, 152, 242],
    'score' => 5,
    'msg' => 'Possible Server Side Request Forgery (SSRF) Attack: URL Parameter using IP Address',
    'rule' => [
      ['w' => ['cookie', 'args', 'files'], 'rx' => '~(?i)(?:a(?:cap|f[ps]|ttachment)|b(?:eshare|itcoin|lob)|c(?:a(?:llto|p)|id|vs|ompress.(?:zlib|bzip2))|d(?:a(?:v|ta)|ict|n(?:s|tp))|e(?:d2k|xpect)|f(?:(?:ee)?d|i(?:le|nger|sh)|tps?)|g(?:it|o(?:pher)?|lob)|h(?:323|ttps?)|i(?:ax|cap|(?:ma|p)ps?|rc[6s]?)|ja(?:bbe)?r|l(?:dap[is]?|ocal_file)|m(?:a(?:ilto|ven)|ms|umble)|n(?:e(?:tdoc|ws)|fs|ntps?)|ogg|p(?:aparazzi|h(?:ar|p)|op(?:2|3s?)|r(?:es|oxy)|syc)|r(?:mi|sync|tm(?:f?p)?|ar)|s(?:3|ftp|ips?|m(?:[bs]|tps?)|n(?:ews|mp)|sh(?:2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?)?|vn(?:\+ssh)?)|t(?:e(?:amspeak|lnet)|ftp|urns?)|u(?:dp|nreal|t2004)|v(?:entrilo|iew-source|nc)|w(?:ebcal|ss?)|x(?:mpp|ri)|zip):/?/?(?:[0-9]{7,10}|(?:0x[0-9a-f]{2}\.){3}0x[0-9a-f]{2}|0x(?:[0-9a-f]{8}|[0-9a-f]{16})|(?:0{1,4}[0-9]{1,3}\.){3}0{1,4}[0-9]{1,3}|[0-9]{1,3}\.(?:[0-9]{1,3}\.[0-9]{5}|[0-9]{8})|(?:\x5c\x5c[\-0-9a-z]\.?_?)+|\[[0-:a-f]+(?:[\.0-9]+|%[0-9A-Z_a-z]+)?\]|[a-z][\-\.0-9A-Z_a-z]{1,255}:[0-9]{1,5}(?:#?[\s\x0b]*&?@(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-z][\-\.0-9A-Z_a-z]{1,255}):[0-9]{1,5}/?)+|[\.0-9]{0,11}(?:\x{e2}(?:\x91[\xa0-\x{bf}]|\x92[\x80-\x{bf}]|\x93[\x80-\x{a9}\x{ab}-\x{bf}])|\x{e3}\x80\x82)+)~'],
    ],
  ],
  [
    'id' => 934140,
    'phase' => 2,
    'pl' => 2,
    'atk_cat' => ['injection_generic', 'rce'],
    'capec' => [1000, 152, 242],
    'score' => 5,
    'msg' => 'Perl Injection Attack',
    'rule' => [
      ['w' => ['cookie', 'args', 'files'], 'rx' => '~@+\{[\s\x0b]*\[~'],
    ],
  ],
  [
    'id' => 934180,
    'phase' => 2,
    'pl' => 2,
    'atk_cat' => ['injection_generic', 'ssti'],
    'capec' => [1000, 152, 242],
    'score' => 5,
    'msg' => 'SSTI Attack',
    'rule' => [
      ['w' => ['cookie', 'args', 'files'], 'rx' => '~(?:\{%[^%}]*%}|<%=?[^%>]*%>)~'],
    ],
  ],
];
<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

return [
  [
    'id' => 931100,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['rfi'],
    'capec' => [1000, 152, 175, 253],
    'score' => 5,
    'msg' => 'Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address',
    'rule' => [
      ['w' => ['uri'], 'rx' => '~(?i)^(file|ftps?|https?|ssh)://(?:\[?[a-f0-9]+:[a-f0-9:]+\]?|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})~'],
    ],
  ],
  [
    'id' => 931110,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['rfi'],
    'capec' => [1000, 152, 175, 253],
    'score' => 5,
    'msg' => 'Possible Remote File Inclusion (RFI) Attack: Common RFI Vulnerable Parameter Name used w/URL Payload',
    'rule' => [
      ['w' => ['uri', 'body'], 'rx' => '~(?i)(?:\binclude\s*\([^)]*|mosConfig_absolute_path|_CONF\[path\]|_SERVER\[DOCUMENT_ROOT\]|GALLERY_BASEDIR|path\[docroot\]|appserv_root|config\[root_dir\])=(?:file|ftps?|https?)://~'],
    ],
  ],
  [
    'id' => 931120,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['rfi'],
    'capec' => [1000, 152, 175, 253],
    'score' => 5,
    'msg' => 'Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?)',
    'rule' => [
      ['w' => ['uri'], 'rx' => '~^(?i:file|ftps?|https?).*?\?+$~'],
    ],
  ],
  [
    'id' => 931130,
    'phase' => 2,
    'pl' => 2,
    'atk_cat' => ['rfi'],
    'capec' => [1000, 152, 175, 253],
    'score' => 5,
    'msg' => 'Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link',
    'rule' => [
      ['w' => ['uri'], 'rx' => '~(?i)(?:(?:url|jar):)?(?:a(?:cap|f[ps]|ttachment)|b(?:eshare|itcoin|lob)|c(?:a(?:llto|p)|id|vs|ompress.(?:zlib|bzip2))|d(?:a(?:v|ta)|ict|n(?:s|tp))|e(?:d2k|xpect)|f(?:(?:ee)?d|i(?:le|nger|sh)|tps?)|g(?:it|o(?:pher)?|lob)|h(?:323|ttps?)|i(?:ax|cap|(?:ma|p)ps?|rc[6s]?)|ja(?:bbe)?r|l(?:dap[is]?|ocal_file)|m(?:a(?:ilto|ven)|ms|umble)|n(?:e(?:tdoc|ws)|fs|ntps?)|ogg|p(?:aparazzi|h(?:ar|p)|op(?:2|3s?)|r(?:es|oxy)|syc)|r(?:mi|sync|tm(?:f?p)?|ar)|s(?:3|ftp|ips?|m(?:[bs]|tps?)|n(?:ews|mp)|sh(?:2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?)?|vn(?:\+ssh)?)|t(?:e(?:amspeak|lnet)|ftp|urns?)|u(?:dp|nreal|t2004)|v(?:entrilo|iew-source|nc)|w(?:ebcal|ss?)|x(?:mpp|ri)|zip)://?(?:[^@]+@)?([^/]*)~'],
    ],
  ],
  [
    'id' => 931131,
    'phase' => 1,
    'pl' => 2,
    'atk_cat' => ['rfi'],
    'capec' => [1000, 152, 175, 253],
    'score' => 5,
    'msg' => 'Possible Remote File Inclusion (RFI) Attack',
    'rule' => [
      ['w' => ['files'], 'rx' => '~(?i)(?:(?:url|jar):)?(?:a(?:cap|f[ps]|ttachment)|b(?:eshare|itcoin|lob)|c(?:a(?:llto|p)|id|vs|ompress.(?:zlib|bzip2))|d(?:a(?:v|ta)|ict|n(?:s|tp))|e(?:d2k|xpect)|f(?:(?:ee)?d|i(?:le|nger|sh)|tps?)|g(?:it|o(?:pher)?|lob)|h(?:323|ttps?)|i(?:ax|cap|(?:ma|p)ps?|rc[6s]?)|ja(?:bbe)?r|l(?:dap[is]?|ocal_file)|m(?:a(?:ilto|ven)|ms|umble)|n(?:e(?:tdoc|ws)|fs|ntps?)|ogg|p(?:aparazzi|h(?:ar|p)|op(?:2|3s?)|r(?:es|oxy)|syc)|r(?:mi|sync|tm(?:f?p)?|ar)|s(?:3|ftp|ips?|m(?:[bs]|tps?)|n(?:ews|mp)|sh(?:2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?)?|vn(?:\+ssh)?)|t(?:e(?:amspeak|lnet)|ftp|urns?)|u(?:dp|nreal|t2004)|v(?:entrilo|iew-source|nc)|w(?:ebcal|ss?)|x(?:mpp|ri)|zip)://(?:[^@]+@)?([^/]*)~'],
    ],
  ],
];
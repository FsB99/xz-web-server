<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

return [
  [
    'id' => 920170,
    'phase' => 1,
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 5,
    'msg' => 'GET or HEAD Request with Body Content',
    'rule' => [
      ['w' => ['method'], 'in' => ['GET', 'HEAD']],
      ['w' => 'header', 'wpr' => 'Content-Length', 'eq' => '0'],
    ],
  ],
  [
    'id' => 920181,
    'phase' => 1,
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 4,
    'msg' => 'Content-Length and Transfer-Encoding headers present',
    'rule' => [
      ['w' => ['header'], 'wpr' => 'Transfer-Encoding', 'eq' => '0'],
      ['w' => ['header'], 'wpr' => 'Content-Length', 'not_eq' => '0'],
    ],
  ],
  [
    'id' => 920660,
    'phase' => 1,
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 4,
    'msg' => 'Obsolete Request-Range header detected',
    'rule' => [
      ['w' => ['header'], 'wpr' => 'Request-Range', 'eq' => '0'],
    ],
  ],
  [
    'id' => 920210,
    'phase' => 1,
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 4,
    'msg' => 'Multiple/Conflicting Connection Header Data Found',
    'rule' => [
      ['w' => ['header'], 'wpr' => 'Connection', 'rx' => '~\b(?:keep-alive|close),\s?(?:keep-alive|close)\b~'],
    ],
  ],
  [
    'id' => 920260,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 255, 153, 267, 72],
    'score' => 4,
    'msg' => 'Unicode Full/Half Width Abuse Attack Attempt',
    'rule' => [
      ['w' => ['body', 'uri'], 'rx' => '~(?i)%uff[0-9a-f]{2}~'],
    ],
  ],
  [
    'id' => 920270,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 5,
    'msg' => 'Invalid character in request (null character)',
     'rule' => [
      ['w' => ['uri'], 'wpr' => '', 'maxl' => 255], // todo, maybe need 1-255
    ],
  ],
  [
    'id' => 920320,
    'phase' => 1,
    'pl' => 2,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 2,
    'msg' => 'Missing User Agent Header',
    'rule' => [
      ['w' => ['header'], 'wpr' => 'User-Agent', 'in' => ['']],
    ],
  ],
  [
    'id' => 920121,
    'phase' => 2,
    'pl' => 2,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 5,
    'msg' => 'Attempted multipart/form-data bypass',
    'rule' => [
      ['w' => ['files', 'files_name'], 'rx' => "~['\";=\x5c]~"],
    ],
  ],
  [
    'id' => 920510,
    'phase' => 1,
    'pl' => 3,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 210, 272],
    'score' => 5,
    'msg' => 'Invalid Cache-Control request header',
    'rule' => [
      ['w' => ['header'], 'wpr' => 'Cache-Control', 'rx' => "~^(?:(?:max-age=[0-9]+|min-fresh=[0-9]+|no-cache|no-store|no-transform|only-if-cached|max-stale(?:=[0-9]+)?)(?:\s*\,\s*|$)){1,7}$~", 'not' => true],
    ],
  ],
  [
    'id' => 920521,
    'phase' => 1,
    'pl' => 3,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 255, 153],
    'score' => 5,
    'msg' => 'Invalid character in request headers (outside of very strict set)',
    'rule' => [
      ['w' => ['header'], 'wpr' => 'Accept-Encoding', 'rx' => "~br|compress|deflate|(?:pack200-)?gzip|identity|\*|^$|aes128gcm|exi|zstd|x-(?:compress|gzip)~", 'not' => true],
    ],
  ],
  [
    'id' => 920275,
    'phase' => 1,
    'pl' => 4,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 255, 153],
    'score' => 5,
    'msg' => 'Invalid character in request headers (outside of very strict set)',
    'rule' => [
      ['w' => ['header'], 'wpr' => 'Sec-Fetch-User', 'rx' => "~^(?:\?[01])?$~", 'not' => true],
    ],
  ],
  [
    'id' => 920275,
    'phase' => 1,
    'pl' => 4,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 255, 153],
    'score' => 5,
    'msg' => 'Invalid character in request headers (outside of very strict set)',
    'rule' => [
      ['w' => ['header'], 'wpr' => 'Sec-CH-UA-Mobile', 'rx' => "~^(?:\?[01])?$~", 'not' => true],
    ],
  ],
  [
    'id' => 920460,
    'phase' => 2,
    'pl' => 4,
    'atk_cat' => ['protocol'],
    'capec' => [1000, 153, 267],
    'score' => 5,
    'msg' => 'Abnormal character escapes in request',
    'rule' => [
      ['w' => ['uri', 'header'], 'rx' => '~(?:^|[^\x5c])\x5c[cdeghijklmpqwxyz123456789]~'],
    ],
  ],
];
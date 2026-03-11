<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

return [
  [
    'id' => 943100,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['fixation'],
    'capec' => [1000, 225, 21, 593, 61],
    'score' => 5,
    'msg' => 'Possible Session Fixation Attack: Setting Cookie Values in HTML',
    'rule' => [
      ['w' => ['cookie', 'args', 'uri'], 'rx' => '~(?i)\.cookie\b.*?;[^0-9A-Z_a-z]*?(?:expires|domain)[^0-9A-Z_a-z]*?=|\bhttp-equiv[^0-9A-Z_a-z]+set-cookie\b~'],
    ],
  ],
  [
    'id' => 943100,
    'phase' => 2,
    'pl' => 1,
    'atk_cat' => ['fixation'],
    'capec' => [1000, 225, 21, 593, 61],
    'score' => 5,
    'msg' => 'Possible Session Fixation Attack: SessionID Parameter Name with Off-Domain Referer',
    'rule' => [
      ['w' => ['args_names', 'uri'], 'rx' => '~^(?:j(?:se(?:ssionid|rvsession)|wsession)|(?:asp(?:\.net_)?session|zend_session_)id|p(?:hpsessi(?:on|d)|lay_session)|(?:(?:w(?:eblogic|l)|rack\.|laravel_)sessio|(?:next-auth\.session-|meteor_login_)toke)n|s(?:(?:ession[\-_]?|ails\.s)id|hiny-token)|_(?:session_id|(?:(?:flask|rails)_sessio|_(?:secure|host)-next-auth\.session-toke)n)|c(?:f(?:s?id|token)|onnect\.sid|akephp|i_session)|koa[\.:]sess)$~'],
    ],
  ],
];
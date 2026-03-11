<?php
// XZ Web Server by Fsb
if (! \defined('ABSPATH')) exit(0);

function gui_homepage(): array {
  return [
    'r_type' => 'html',
    'r_code' => 200,
    'r_header' => [
      'Content-Type' => 'text/html',
    ],
    'r_body' => 'This is Homepage',
  ];
}
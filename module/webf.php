<?php
// XZ Web Server by Fsb
declare(strict_types=1);

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

function gui_testpage(): array {
  return [
    'r_type' => 'html',
    'r_code' => 200,
    'r_header' => [
      'Content-Type' => 'text/html',
    ],
    'r_body' => 'This is Test page',
  ];
}
# Notes
- 12-03-2026
  - Fix some minor HTTP parser.
  - Experimental with few WAF engines but its seem this is the less buggy.
  - Changed WAF test, since curl fixing the bad requests thus generated bad tests.
  - Adding xhprof / profiling.
  
- 11-03-2026
  - Change HTTP parser.
  - Adding static code analysis PHPStan(SAST).
  - Change the implementation of CRS engine to reduce the performance degraded (-14.4%).
  - Change regex's for compatibility with PHP.
  - Use multi process for faster tests.
  - Tests using CRS regression tests as pivot, failed: 194 / 3.360.
  - Adding ASCII table.

- 10-03-2026
  - Fix some minor HTTP
  - Adding OWASP CRS tests as pivot to see how good the implementation is (pilot)
  - Adding partial implementation of CRS.
  - Fix CRS engine.

- 09-03-2026
  - Changed into modules
  - Moved core from server.php to module/http.php
  - Configable server.php
  - Routes function call to module/webf.php
  - Adding module HTTP fast routing
  - Adding module Firewall

- 26-02-2026
  -  Partial RFC 7230, 9112, 7231 & 9110
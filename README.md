# XZ Web Server
XZ Web Server is a minimal high performance php web server. not a HTTP RFC fully compliance.

# Get Started

``` console
php server.php
```

# Performance

| Product | Performance. RPS |
| --- | --- |
| Go (std http) | ~209.734 |
| XZ (Unix) | ~326.849 |
| XZ (Unix with EV) | ~347.768 |

# Notes
- Partial RFC 7230, 9112, 7231 & 9110
- Changed into modules
- Moved core from server.php to module/http.php
- Configable server.php
- Routes function call to module/webf.php
- Adding fast routing
# XZ Web Server
XZ Web Server is a minimal high performance php web server, with fast routing and modules such as: firewall. not a full HTTP RFC compliance.

# Modules
## HTTP
A partial implementation of HTTP RFC server, classless. 

## Firewall
A partial implementation of OWASP Core RuleSet(CRS) only use phase 1 and 2, and cut down the rules to reduce the performance degraded. 

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

# NOTES
[Developer Notes Link](https://github.com/FsB99/xz-web-server/blob/main/Notes.md)

# Testing

``` console
// for SAST
php test.php

// for WAF
php test.php -a waf
```
// Package caddywaf provides Web Application Firewall (WAF) functionality as a Caddy module.
//
// Module ID: http.handlers.waf
// Module type: HTTP handler middleware
//
// This module implements comprehensive web security features including:
//   - Regex-based request filtering
//   - IP and DNS blacklisting
//   - Geographic access control
//   - Rate limiting with configurable windows
//   - Anomaly detection and scoring
//   - Multi-phase request inspection
//   - Real-time metrics and monitoring
//   - Custom response handling
//   - Dynamic configuration reloading
//
// Installation:
//   xcaddy build --with github.com/fabriziosalmi/caddy-waf
//
// Basic usage in Caddyfile:
//   waf {
//       rule_file rules.json
//       ip_blacklist_file blacklist.txt
//       metrics_endpoint /waf_metrics
//   }
//
// For complete documentation, see: https://github.com/fabriziosalmi/caddy-waf
package caddywaf
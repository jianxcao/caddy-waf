# Caddy WAF Module Information

**Module Name:** caddy-waf  
**Module ID:** `http.handlers.waf`  
**Go Module Path:** `github.com/fabriziosalmi/caddy-waf`  
**License:** AGPLv3  
**Latest Version:** v0.0.6  

## Description

A robust, highly customizable, and feature-rich Web Application Firewall (WAF) middleware for the Caddy web server. This middleware provides advanced protection against a comprehensive range of web-based threats, seamlessly integrating with Caddy and offering flexible configuration options to secure your applications effectively.

## Module Type

HTTP Handler Middleware (`http.handlers.waf`)

## Features

- **Regex-Based Filtering:** Deep URL, data & header inspection using powerful regex rules
- **Blacklisting:** Blocks malicious IPs, domains & optionally TOR exit nodes
- **Geo-Blocking:** Restricts access by country using GeoIP
- **Rate Limiting:** Prevents abuse via customizable IP request limits
- **Anomaly Scoring:** Dynamically blocks requests based on cumulative rule matches
- **Multi-Phase Inspection:** Analyzes traffic throughout the request lifecycle
- **Sensitive Data Redaction:** Removes private info from logs
- **Custom Response Handling:** Tailored responses for blocked requests
- **Detailed Monitoring:** JSON endpoint for performance tracking & analysis
- **Dynamic Config Reloads:** Seamless updates without restarts

## Installation

```bash
xcaddy build --with github.com/fabriziosalmi/caddy-waf
```

## Basic Usage

```caddyfile
example.com {
    waf {
        rule_file rules.json
        ip_blacklist_file ip_blacklist.txt
        dns_blacklist_file dns_blacklist.txt
        metrics_endpoint /waf_metrics
    }
    
    respond "Protected by Caddy WAF"
}
```

## Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `rule_file` | string | Path to WAF rules JSON file |
| `ip_blacklist_file` | string | Path to IP blacklist file |
| `dns_blacklist_file` | string | Path to DNS blacklist file |
| `metrics_endpoint` | string | Endpoint for WAF metrics |
| `anomaly_threshold` | int | Threshold for anomaly detection |
| `rate_limit` | block | Rate limiting configuration |
| `country_block` | block | Country blocking configuration |
| `custom_response` | block | Custom response configuration |
| `log_level` | string | Logging level (debug, info, warn, error) |
| `log_file` | string | Path to log file |

## Documentation

Complete documentation is available in the [docs directory](https://github.com/fabriziosalmi/caddy-waf/tree/main/docs).

## Repository

https://github.com/fabriziosalmi/caddy-waf

## Support

For issues and support, please visit the [GitHub Issues page](https://github.com/fabriziosalmi/caddy-waf/issues).
# 🌍 Country Blocking and Whitelisting

*   Uses the MaxMind GeoIP2 database for country lookups.
*   Download the `GeoLite2-Country.mmdb` file (see [Installation](#-installation)).
*   Use `block_countries` or `whitelist_countries` with ISO country codes:

## Priorities
`Whitelisting` has a **higher** priority than `Blacklisting`.

### Config Example

Whitelist: BR <br>
Blacklist: US, UK <br>

Q: Which is THE priority ? <br>
A: BR IPs are allowed, all others are **blocked**

## Global blocking priorities

- IP blacklist
- DNS blacklist 
- Rate limit
- Whitelist
- Blacklist

## Config example
```caddyfile
# Block requests from Russia, China, and North Korea
block_countries /path/to/GeoLite2-Country.mmdb RU CN KP

# Whitelist requests from the United States
whitelist_countries /path/to/GeoLite2-Country.mmdb US
```

//go:build it

package caddywaf_test

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
	_ "github.com/fabriziosalmi/caddy-waf"
)

func TestWaf_IPBlacklisting(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}
	http://localhost:9080 {
		route {
			waf {
				anomaly_threshold 20
				rule_file rules.json

				ip_blacklist_file ip_blacklist.txt
				dns_blacklist_file dns_blacklist.txt
				log_severity info
			}
		}
		respond "Hello, World!"
	}
	`, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/", 200, "Hello, World!")
}

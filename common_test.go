package caddywaf

import "net/http"

const (
	geoIPdata  = "GeoLite2-Country.mmdb"
	localIP    = "127.0.0.1"
	aliCNIP    = "47.88.198.38"
	googleUSIP = "74.125.131.105"
	googleBRIP = "128.201.228.12"
	googleRUIP = "74.125.131.94"
	testURL    = "http://example.com"
	torListURL = "https://cdn.nws.neurodyne.pro/nws-cdn-ut8hw561/waf/torbulkexitlist" // custom TOR list URL for testing
)

var customResponse = map[int]CustomBlockResponse{
	403: {
		StatusCode: http.StatusForbidden,
		Body:       "Access Denied",
	},
}

package caddywaf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewGeoIPHandler(t *testing.T) {
	logger := zap.NewNop()
	handler := NewGeoIPHandler(logger)

	if handler == nil {
		t.Error("NewGeoIPHandler returned nil")
		return
	}

	if handler.logger == nil {
		t.Error("Logger not initialized")
	}
}

func TestWithGeoIPCache(t *testing.T) {
	handler := NewGeoIPHandler(nil)
	ttl := 5 * time.Minute
	handler.WithGeoIPCache(ttl)

	if handler.geoIPCache == nil {
		t.Error("Cache not initialized")
	}

	if handler.geoIPCacheTTL != ttl {
		t.Errorf("Expected TTL %v, got %v", ttl, handler.geoIPCacheTTL)
	}
}

func TestLoadGeoIPDatabase(t *testing.T) {
	handler := NewGeoIPHandler(nil)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "Empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "Invalid path",
			path:    "/invalid/path/db.mmdb",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := handler.LoadGeoIPDatabase(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadGeoIPDatabase() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsCountryInList(t *testing.T) {
	handler := NewGeoIPHandler(nil)

	tests := []struct {
		name        string
		remoteAddr  string
		countryList []string
		wantErr     bool
	}{
		{
			name:        "Nil GeoIP database",
			remoteAddr:  "192.168.1.1",
			countryList: []string{"US"},
			wantErr:     true,
		},
		{
			name:        "Invalid IP",
			remoteAddr:  "invalid-ip",
			countryList: []string{"US"},
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := handler.IsCountryInList(tt.remoteAddr, tt.countryList, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsCountryInList() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetCountryCode(t *testing.T) {
	handler := NewGeoIPHandler(nil)

	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{
			name:       "Nil GeoIP database",
			remoteAddr: "192.168.1.1",
			want:       "N/A",
		},
		{
			name:       "Invalid IP",
			remoteAddr: "invalid-ip",
			want:       "N/A",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := handler.GetCountryCode(tt.remoteAddr, nil); got != tt.want {
				t.Errorf("GetCountryCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestWithGeoIPLookupFallbackBehaviorSetup tests the WithGeoIPLookupFallbackBehavior method setup.
func TestWithGeoIPLookupFallbackBehaviorSetup(t *testing.T) {
	logger := zap.NewNop()
	handler := NewGeoIPHandler(logger)

	handler.WithGeoIPLookupFallbackBehavior("default")
	assert.Equal(t, "default", handler.geoIPLookupFallbackBehavior)
}

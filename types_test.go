package caddywaf

import (
	"regexp"
	"testing"
)

func TestNewRuleCache(t *testing.T) {
	cache := NewRuleCache()
	if cache == nil {
		t.Fatal("NewRuleCache() returned nil")
	}
	if cache.rules == nil {
		t.Fatal("NewRuleCache() created a cache with nil rules map")
	}
}

func TestRuleCache_GetSet(t *testing.T) {
	cache := NewRuleCache()
	testRegex := regexp.MustCompile(`test.*`)

	// Test Set
	cache.Set("rule1", testRegex)

	// Test Get
	got, exists := cache.Get("rule1")
	if !exists {
		t.Error("RuleCache.Get() returned exists=false for existing rule")
	}
	if got != testRegex {
		t.Error("RuleCache.Get() returned wrong regex")
	}

	// Test Get for non-existent rule
	_, exists = cache.Get("nonexistent")
	if exists {
		t.Error("RuleCache.Get() returned exists=true for non-existent rule")
	}
}

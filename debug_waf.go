package caddywaf

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DebugRequest logs detailed information about a request for debugging
func (m *Middleware) DebugRequest(r *http.Request, state *WAFState, msg string) {
	if m.LogSeverity != "debug" {
		return
	}

	var ruleIDs []string
	var scores []string

	// Log all matched rules and their scores
	m.ruleHits.Range(func(key, value interface{}) bool {
		ruleID, ok := key.(RuleID)
		if !ok {
			return true
		}
		hitCount, ok := value.(HitCount)
		if !ok {
			return true
		}
		ruleIDs = append(ruleIDs, string(ruleID))
		scores = append(scores, fmt.Sprintf("%s:%d", string(ruleID), hitCount))
		return true
	})

	// Create a detailed debug log
	m.logger.Debug(fmt.Sprintf("WAF DEBUG: %s", msg),
		zap.String("timestamp", time.Now().Format(time.RFC3339)),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("query", r.URL.RawQuery),
		zap.Int("total_score", state.TotalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
		zap.Bool("blocked", state.Blocked),
		zap.Int("status_code", state.StatusCode),
		zap.Bool("response_written", state.ResponseWritten),
		zap.String("matched_rules", strings.Join(ruleIDs, ",")),
		zap.String("rule_scores", strings.Join(scores, ",")),
	)
}

// DumpRulesToFile dumps the loaded rules to a file for inspection
func (m *Middleware) DumpRulesToFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	f.WriteString("=== WAF Rules Dump ===\n\n")

	for phase := 1; phase <= 4; phase++ {
		f.WriteString(fmt.Sprintf("== Phase %d Rules ==\n", phase))
		rules, ok := m.Rules[phase]
		if !ok || len(rules) == 0 {
			f.WriteString("  No rules for this phase\n\n")
			continue
		}

		for i, rule := range rules {
			f.WriteString(fmt.Sprintf("  Rule %d:\n", i+1))
			f.WriteString(fmt.Sprintf("    ID: %s\n", rule.ID))
			f.WriteString(fmt.Sprintf("    Pattern: %s\n", rule.Pattern))
			f.WriteString(fmt.Sprintf("    Targets: %v\n", rule.Targets))
			f.WriteString(fmt.Sprintf("    Score: %d\n", rule.Score))
			f.WriteString(fmt.Sprintf("    Action: %s\n", rule.Action))
			f.WriteString(fmt.Sprintf("    Description: %s\n", rule.Description))
			f.WriteString("\n")
		}
	}

	return nil
}

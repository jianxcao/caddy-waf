package caddywaf

import (
	"bytes"
	"fmt"
	"net/http"

	"go.uber.org/zap"
)

// allowRequest - handles request allowing
func (m *Middleware) allowRequest(state *WAFState) {
	state.Blocked = false
	state.StatusCode = http.StatusOK
	state.ResponseWritten = false

	m.incrementAllowedRequestsMetric()
}

// blockRequest handles blocking a request and logging the details.
func (m *Middleware) blockRequest(recorder http.ResponseWriter, r *http.Request, state *WAFState, statusCode int, reason, ruleID, matchedValue string, fields ...zap.Field) {
	// CRITICAL FIX: Set these flags before any other operations
	state.Blocked = true
	state.StatusCode = statusCode
	state.ResponseWritten = true

	// CRITICAL FIX: Log at WARN level for visibility
	m.logger.Warn("REQUEST BLOCKED BY WAF", append(fields,
		zap.String("rule_id", ruleID),
		zap.String("reason", reason),
		zap.Int("status_code", statusCode),
		zap.String("remote_addr", r.RemoteAddr),
		zap.Int("total_score", state.TotalScore))...)

	// CRITICAL FIX: Increment blocked metrics immediately
	m.incrementBlockedRequestsMetric()

	// Write a simple text response for blocked requests
	recorder.Header().Set("Content-Type", "text/plain")
	recorder.WriteHeader(statusCode)

	if m.CustomResponses != nil {
		m.writeCustomResponse(recorder, state.StatusCode)
	} else {
		message := fmt.Sprintf("Request blocked by WAF. Reason: %s", reason)
		if _, err := recorder.Write([]byte(message)); err != nil {
			m.logger.Error("Failed to write blocked response", zap.Error(err))
		}
	}
}

// responseRecorder captures the response status code, headers, and body.
type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	written    bool // To track if a write to the original writer has been done.
}

// NewResponseRecorder creates a new responseRecorder.
func NewResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		body:           new(bytes.Buffer),
		statusCode:     0, // Zero means not explicitly set
		written:        false,
	}
}

// WriteHeader captures the response status code.
func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

// Header returns the response headers.
func (r *responseRecorder) Header() http.Header {
	return r.ResponseWriter.Header()
}

// BodyString returns the captured response body as a string.
func (r *responseRecorder) BodyString() string {
	return r.body.String()
}

// StatusCode returns the captured status code.
func (r *responseRecorder) StatusCode() int {
	if r.statusCode == 0 {
		return http.StatusOK
	}
	return r.statusCode
}

// Write captures the response body and writes to the buffer only.
func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.statusCode == 0 && !r.written {
		r.WriteHeader(http.StatusOK) // Default to 200 if not set
	}
	n, err := r.body.Write(b)
	r.written = true
	return n, err
}

package node

import (
	"bytes"
	"testing"
	"time"
)

func TestIngressLogHasGlobalRateLimit(t *testing.T) {
	var output bytes.Buffer
	logger := &rateLimitedLogger{writer: &output, interval: time.Second, limit: 20}
	for i := 0; i < 25; i++ {
		logger.Printf("event %d\n", i)
	}
	if got := bytes.Count(output.Bytes(), []byte("event ")); got != 20 {
		t.Fatalf("wrote %d messages, want 20", got)
	}
}

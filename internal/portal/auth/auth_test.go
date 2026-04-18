package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(rate.Limit(2), 2)
	ip := "192.168.1.1"

	// First two allowed
	assert.True(t, rl.Allow(ip))
	assert.True(t, rl.Allow(ip))
	// Third denied
	assert.False(t, rl.Allow(ip))

	// Wait for token refill (approx 0.5s for rate 2/s)
	time.Sleep(600 * time.Millisecond)
	assert.True(t, rl.Allow(ip))
}

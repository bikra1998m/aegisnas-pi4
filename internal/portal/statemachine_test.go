package portal

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestStateMachine(t *testing.T) {
	logger := zap.NewNop()
	sm := NewStateMachine(logger)

	mac := "aa:bb:cc:dd:ee:ff"
	ip := "10.20.0.100"

	// GetOrCreate
	client := sm.GetOrCreate(mac, ip)
	assert.Equal(t, StateUnauthenticated, client.State)
	assert.True(t, sm.ShouldRedirect(mac))

	// Transition to authenticated
	err := sm.Transition(mac, StateAuthenticated, "testuser", "session123")
	assert.NoError(t, err)
	assert.True(t, sm.IsAuthenticated(mac))
	assert.False(t, sm.ShouldRedirect(mac))

	// GetClient
	c, ok := sm.GetClient(mac)
	assert.True(t, ok)
	assert.Equal(t, "testuser", c.Username)
	assert.Equal(t, StateAuthenticated, c.State)
}

func TestCleanupIdle(t *testing.T) {
	logger := zap.NewNop()
	sm := NewStateMachine(logger)

	mac1 := "aa:bb:cc:dd:ee:01"
	mac2 := "aa:bb:cc:dd:ee:02"
	sm.GetOrCreate(mac1, "10.0.0.1")
	sm.GetOrCreate(mac2, "10.0.0.2")

	// Manually set one client's LastSeen to old time
	sm.mu.Lock()
	sm.clients[mac1].LastSeen = time.Now().Add(-20 * time.Minute)
	sm.mu.Unlock()

	sm.CleanupIdle(10 * time.Minute)

	_, exists := sm.GetClient(mac1)
	assert.False(t, exists, "idle client should be removed")
	_, exists = sm.GetClient(mac2)
	assert.True(t, exists, "active client should remain")
}

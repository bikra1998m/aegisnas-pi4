package subscriber

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplySubscriberStateMachineHappyPath(t *testing.T) {
	path := []struct {
		from  string
		event string
		to    State
	}{
		{"new", "discovery", StateDiscovered},
		{"discovered", "access-request", StateAuthenticating},
		{"authenticating", "access-accept", StateAuthorized},
		{"authorized", "address-assigned", StateAddressAssigned},
		{"address_assigned", "service-activate", StateServiceActive},
		{"service_active", "accounting-start", StateAccountingStarted},
		{"accounting_started", "accounting-interim", StateInterimSeen},
		{"interim_seen", "policy-update", StatePolicyUpdatePending},
		{"policy_update_pending", "coa-ack", StateAccountingStarted},
		{"accounting_started", "accounting-stop", StateStopped},
	}
	for _, step := range path {
		decision, err := Apply(step.from, step.event)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, step.to, decision.Transition.To)
	}
}

func TestApplySubscriberStateMachineRejectsInvalidTransition(t *testing.T) {
	decision, err := Apply("new", "accounting-start")
	require.NoError(t, err)

	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "not valid")
	assert.Equal(t, StateNew, decision.Transition.To)
}

func TestApplySubscriberStateMachineRejectsUnknownInputs(t *testing.T) {
	_, err := Apply("mystery", "discovery")
	assert.ErrorContains(t, err, "state")

	_, err = Apply("new", "mystery")
	assert.ErrorContains(t, err, "event")
}

func TestCanonicalTransitionsExposeRecoveryAndAccounting(t *testing.T) {
	transitions := CanonicalTransitions()
	assert.GreaterOrEqual(t, len(transitions), 20)

	var accounting, recovery bool
	for _, transition := range transitions {
		if transition.Accounting {
			accounting = true
		}
		if transition.Recoverable {
			recovery = true
		}
	}
	assert.True(t, accounting)
	assert.True(t, recovery)
}

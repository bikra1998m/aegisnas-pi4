package db

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutboundDACRequestLifecycleRedactsSensitiveHistory(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	t.Cleanup(func() { Close() })
	require.NoError(t, Migrate())

	created, err := CreateOutboundDACRequest(OutboundDACCreate{
		RequestID:        "dac-test-1",
		Action:           "coa",
		Status:           OutboundDACStatusSent,
		TargetAddress:    "192.0.2.10",
		TargetPort:       3799,
		TargetTransport:  "udp",
		NASIdentifier:    "branch-ap",
		NASIPAddress:     "192.0.2.10",
		NASType:          "cisco",
		ShortName:        "branch-ap",
		SessionID:        "acct-123",
		Username:         "Alice@example.test",
		CallingStationID: "AA-BB-CC-DD-EE-FF",
		FramedIPAddress:  "192.0.2.100",
		Attributes: []OutboundDACAttribute{
			{Name: "User-Name", Value: "Alice@example.test"},
			{Name: "Calling-Station-Id", Value: "AA-BB-CC-DD-EE-FF"},
			{Name: "Filter-Id", Value: "employee"},
			{Name: "Class", Value: "opaque-state"},
		},
		RequestCode:          43,
		CorrelationID:        "corr-1",
		RequestedBy:          "ops@example.test",
		RequestedAt:          time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC),
		SentAt:               time.Date(2026, 5, 5, 12, 0, 1, 0, time.UTC),
		MessageAuthenticator: true,
		RequestFingerprint:   "request-sha",
	}, 100)
	require.NoError(t, err)
	assert.Equal(t, OutboundDACStatusSent, created.Status)
	assert.Equal(t, HashEAPIdentity("Alice@example.test"), created.UsernameHash)
	assert.Equal(t, HashEAPIdentity("AA-BB-CC-DD-EE-FF"), created.CallingStationHash)
	assert.NotContains(t, outboundDACAttributeValues(created.Attributes), "Alice@example.test")
	assert.NotContains(t, outboundDACAttributeValues(created.Attributes), "AA-BB-CC-DD-EE-FF")
	assert.Contains(t, outboundDACAttributeValues(created.Attributes), "employee")

	require.NoError(t, RecordOutboundDACAttempt(OutboundDACAttemptCreate{
		RequestID:           "dac-test-1",
		Attempt:             1,
		Status:              OutboundDACStatusACK,
		TargetAddress:       "192.0.2.10",
		TargetPort:          3799,
		TargetTransport:     "udp",
		RequestCode:         43,
		ResponseCode:        44,
		LatencyMS:           15,
		PacketIdentifier:    7,
		RequestFingerprint:  "request-sha",
		ResponseFingerprint: "response-sha",
	}))

	completed, err := CompleteOutboundDACRequest(OutboundDACComplete{
		RequestID:           "dac-test-1",
		Status:              OutboundDACStatusACK,
		ResponseCode:        44,
		ReplyMessage:        "updated",
		CompletedAt:         time.Date(2026, 5, 5, 12, 0, 2, 0, time.UTC),
		LatencyMS:           15,
		ResponseFingerprint: "response-sha",
	})
	require.NoError(t, err)
	assert.Equal(t, OutboundDACStatusACK, completed.Status)
	assert.Equal(t, "updated", completed.ReplyMessage)

	requests, err := ListOutboundDACRequests(OutboundDACRequestQuery{Status: OutboundDACStatusACK, Limit: 10})
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, "dac-test-1", requests[0].RequestID)

	attempts, err := ListOutboundDACAttempts("dac-test-1", 10)
	require.NoError(t, err)
	require.Len(t, attempts, 1)
	assert.Equal(t, OutboundDACStatusACK, attempts[0].Status)

	summary, err := GetOutboundDACSummary(100)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalRequests)
	assert.Equal(t, 1, summary.ACKCount)
	assert.Equal(t, 1, summary.AttemptCount)
}

func TestOutboundDACRetentionPrunesOldRequestsAndAttempts(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	t.Cleanup(func() { Close() })
	require.NoError(t, Migrate())

	for i := 0; i < 3; i++ {
		requestID := "dac-retention-" + string(rune('a'+i))
		_, err := CreateOutboundDACRequest(OutboundDACCreate{
			RequestID:            requestID,
			Action:               "disconnect",
			Status:               OutboundDACStatusSent,
			TargetAddress:        "192.0.2.10",
			TargetPort:           3799,
			TargetTransport:      "udp",
			Attributes:           []OutboundDACAttribute{{Name: "Acct-Session-Id", Value: requestID}},
			RequestCode:          40,
			CorrelationID:        requestID,
			RequestedAt:          time.Date(2026, 5, 5, 12, i, 0, 0, time.UTC),
			MessageAuthenticator: true,
			RequestFingerprint:   requestID + "-sha",
		}, 2)
		require.NoError(t, err)
		require.NoError(t, RecordOutboundDACAttempt(OutboundDACAttemptCreate{
			RequestID:          requestID,
			Attempt:            1,
			Status:             OutboundDACStatusError,
			TargetAddress:      "192.0.2.10",
			TargetPort:         3799,
			TargetTransport:    "udp",
			RequestCode:        40,
			RequestFingerprint: requestID + "-sha",
			ErrorMessage:       "timeout",
		}))
	}

	requests, err := ListOutboundDACRequests(OutboundDACRequestQuery{Limit: 10})
	require.NoError(t, err)
	require.Len(t, requests, 2)
	assert.Equal(t, "dac-retention-c", requests[0].RequestID)
	assert.Equal(t, "dac-retention-b", requests[1].RequestID)

	attempts, err := ListOutboundDACAttempts("", 10)
	require.NoError(t, err)
	require.Len(t, attempts, 2)
	for _, attempt := range attempts {
		assert.NotEqual(t, "dac-retention-a", attempt.RequestID)
	}
}

func outboundDACAttributeValues(attrs []OutboundDACAttribute) string {
	values := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		values = append(values, attr.Value)
	}
	return strings.Join(values, "|")
}

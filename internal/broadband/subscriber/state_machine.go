package subscriber

import (
	"fmt"
	"strings"
)

type State string

const (
	StateNew                 State = "new"
	StateDiscovered          State = "discovered"
	StateAuthenticating      State = "authenticating"
	StateAuthorized          State = "authorized"
	StateAddressAssigned     State = "address_assigned"
	StateServiceActive       State = "service_active"
	StateAccountingStarted   State = "accounting_started"
	StateInterimSeen         State = "interim_seen"
	StatePolicyUpdatePending State = "policy_update_pending"
	StateReconnecting        State = "reconnecting"
	StateSuspended           State = "suspended"
	StateDisconnecting       State = "disconnecting"
	StateStopped             State = "stopped"
	StateRecovered           State = "recovered"
	StateFailed              State = "failed"
)

type Event string

const (
	EventDiscovery          Event = "discovery"
	EventAccessRequest      Event = "access-request"
	EventAccessAccept       Event = "access-accept"
	EventAccessReject       Event = "access-reject"
	EventAddressAssigned    Event = "address-assigned"
	EventServiceActivate    Event = "service-activate"
	EventAccountingStart    Event = "accounting-start"
	EventAccountingInterim  Event = "accounting-interim"
	EventPolicyUpdate       Event = "policy-update"
	EventCoAAck             Event = "coa-ack"
	EventReconnectRequest   Event = "reconnect-request"
	EventReconnectRecovered Event = "reconnect-recovered"
	EventAccountingStop     Event = "accounting-stop"
	EventDisconnect         Event = "disconnect"
	EventRecoveryScan       Event = "recovery-scan"
	EventFailure            Event = "failure"
)

type Transition struct {
	From        State    `json:"from"`
	Event       Event    `json:"event"`
	To          State    `json:"to"`
	Required    bool     `json:"required"`
	Actions     []string `json:"actions"`
	Accounting  bool     `json:"accounting"`
	Recoverable bool     `json:"recoverable"`
	Description string   `json:"description"`
}

type Decision struct {
	Transition Transition `json:"transition"`
	Allowed    bool       `json:"allowed"`
	Reason     string     `json:"reason,omitempty"`
}

var canonicalTransitions = []Transition{
	{StateNew, EventDiscovery, StateDiscovered, true, []string{"bind access circuit", "record discovery evidence"}, false, true, "Access circuit or PPPoE discovery creates a pending subscriber context."},
	{StateDiscovered, EventAccessRequest, StateAuthenticating, true, []string{"correlate identity", "attach NAS and circuit attributes"}, false, true, "RADIUS Access-Request moves the subscriber into authentication."},
	{StateAuthenticating, EventAccessAccept, StateAuthorized, true, []string{"select product", "render authorization attributes"}, false, true, "Access-Accept authorizes the selected product and role."},
	{StateAuthenticating, EventAccessReject, StateFailed, true, []string{"record rejection", "release pending resources"}, false, false, "Access-Reject closes the pending subscriber context."},
	{StateAuthorized, EventAddressAssigned, StateAddressAssigned, true, []string{"allocate IPv4/IPv6 leases", "bind delegated prefix"}, false, true, "Address assignment binds pools, leases, and delegated prefixes."},
	{StateAddressAssigned, EventServiceActivate, StateServiceActive, true, []string{"activate service legs", "publish route and QoS intent"}, false, true, "Service activation attaches route, QoS, NAT, multicast, and wholesale legs."},
	{StateServiceActive, EventAccountingStart, StateAccountingStarted, true, []string{"open accounting ledger", "correlate Acct-Session-Id"}, true, true, "Accounting-Start makes the subscriber session operationally durable."},
	{StateAccountingStarted, EventAccountingInterim, StateInterimSeen, true, []string{"update counters", "refresh quota and charging hooks"}, true, true, "Accounting-Interim refreshes counters, quota, charging, and support evidence."},
	{StateInterimSeen, EventAccountingInterim, StateInterimSeen, false, []string{"update counters", "refresh quota and charging hooks"}, true, true, "Repeated interim updates keep the service active."},
	{StateAccountingStarted, EventPolicyUpdate, StatePolicyUpdatePending, false, []string{"stage policy delta", "prepare CoA"}, false, true, "Quota, posture, or product changes stage a policy transition."},
	{StateInterimSeen, EventPolicyUpdate, StatePolicyUpdatePending, false, []string{"stage policy delta", "prepare CoA"}, false, true, "Quota, posture, or product changes stage a policy transition."},
	{StatePolicyUpdatePending, EventCoAAck, StateAccountingStarted, true, []string{"commit policy revision", "record CoA acknowledgement"}, false, true, "Successful CoA commits a live policy transition."},
	{StateAccountingStarted, EventReconnectRequest, StateReconnecting, false, []string{"preserve ownership lease", "start reconnect timer"}, false, true, "Reconnect handling preserves subscriber ownership across access flaps."},
	{StateInterimSeen, EventReconnectRequest, StateReconnecting, false, []string{"preserve ownership lease", "start reconnect timer"}, false, true, "Reconnect handling preserves subscriber ownership across access flaps."},
	{StateReconnecting, EventReconnectRecovered, StateAccountingStarted, false, []string{"rebind access circuit", "resume accounting correlation"}, true, true, "Recovered reconnect resumes the same subscriber service context."},
	{StateAccountingStarted, EventAccountingStop, StateStopped, true, []string{"close accounting ledger", "release leases and service legs"}, true, false, "Accounting-Stop cleanly releases subscriber state."},
	{StateInterimSeen, EventAccountingStop, StateStopped, true, []string{"close accounting ledger", "release leases and service legs"}, true, false, "Accounting-Stop cleanly releases subscriber state."},
	{StatePolicyUpdatePending, EventDisconnect, StateDisconnecting, true, []string{"send disconnect", "rollback pending policy"}, false, false, "Disconnect tears down an unsafe pending policy transition."},
	{StateAccountingStarted, EventDisconnect, StateDisconnecting, true, []string{"send disconnect", "close services"}, false, false, "Disconnect tears down the active session."},
	{StateDisconnecting, EventAccountingStop, StateStopped, true, []string{"close accounting ledger", "release resources"}, true, false, "Stop after disconnect finalizes cleanup."},
	{StateReconnecting, EventRecoveryScan, StateRecovered, false, []string{"mark recovered", "emit recovery evidence"}, false, true, "Recovery scan reconciles stale reconnect state."},
	{StateRecovered, EventAccountingInterim, StateInterimSeen, false, []string{"refresh counters", "clear recovery marker"}, true, true, "Interim after recovery resumes normal accounting."},
	{StateSuspended, EventPolicyUpdate, StatePolicyUpdatePending, false, []string{"stage restore policy", "prepare CoA"}, false, true, "Suspended subscribers can be restored by a policy transition."},
	{StateServiceActive, EventFailure, StateFailed, true, []string{"fail closed", "release pending service resources"}, false, false, "Service activation failure fails closed before accounting starts."},
}

func CanonicalTransitions() []Transition {
	out := make([]Transition, len(canonicalTransitions))
	copy(out, canonicalTransitions)
	return out
}

func ValidState(value string) bool {
	_, ok := parseState(value)
	return ok
}

func ValidEvent(value string) bool {
	_, ok := parseEvent(value)
	return ok
}

func Apply(current, event string) (Decision, error) {
	state, ok := parseState(current)
	if !ok {
		return Decision{}, fmt.Errorf("subscriber state %q is invalid", current)
	}
	ev, ok := parseEvent(event)
	if !ok {
		return Decision{}, fmt.Errorf("subscriber event %q is invalid", event)
	}
	for _, transition := range canonicalTransitions {
		if transition.From == state && transition.Event == ev {
			return Decision{Transition: transition, Allowed: true}, nil
		}
	}
	return Decision{
		Transition: Transition{From: state, Event: ev, To: state},
		Allowed:    false,
		Reason:     fmt.Sprintf("event %s is not valid from state %s", ev, state),
	}, nil
}

func parseState(value string) (State, bool) {
	switch State(strings.ToLower(strings.TrimSpace(value))) {
	case StateNew, StateDiscovered, StateAuthenticating, StateAuthorized, StateAddressAssigned, StateServiceActive,
		StateAccountingStarted, StateInterimSeen, StatePolicyUpdatePending, StateReconnecting, StateSuspended,
		StateDisconnecting, StateStopped, StateRecovered, StateFailed:
		return State(strings.ToLower(strings.TrimSpace(value))), true
	default:
		return "", false
	}
}

func parseEvent(value string) (Event, bool) {
	switch Event(strings.ToLower(strings.TrimSpace(value))) {
	case EventDiscovery, EventAccessRequest, EventAccessAccept, EventAccessReject, EventAddressAssigned, EventServiceActivate,
		EventAccountingStart, EventAccountingInterim, EventPolicyUpdate, EventCoAAck, EventReconnectRequest,
		EventReconnectRecovered, EventAccountingStop, EventDisconnect, EventRecoveryScan, EventFailure:
		return Event(strings.ToLower(strings.TrimSpace(value))), true
	default:
		return "", false
	}
}

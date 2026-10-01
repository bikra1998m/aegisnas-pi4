package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateBroadbandAddressLeaseConfigAcceptsProductDerivedAndExplicitPools(t *testing.T) {
	leases := broadbandAddressLeaseValidationFixture()
	subscriber := broadbandAddressLeaseSubscriberFixture()
	pppoe := BroadbandPPPoEConfig{Enabled: true, SessionOwnershipRequired: true}
	radius := broadbandAddressLeaseRadiusFixture()

	require.NoError(t, validateBroadbandAddressLeaseConfig(leases, subscriber, pppoe, radius, "enterprise"))
}

func TestValidateBroadbandAddressLeaseConfigBlocksMissingDependencies(t *testing.T) {
	leases := broadbandAddressLeaseValidationFixture()
	subscriber := broadbandAddressLeaseSubscriberFixture()
	pppoe := BroadbandPPPoEConfig{Enabled: true, SessionOwnershipRequired: true}
	radius := broadbandAddressLeaseRadiusFixture()
	radius.DynamicAuth.Enabled = false

	err := validateBroadbandAddressLeaseConfig(leases, subscriber, pppoe, radius, "enterprise")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "coa_on_conflict")
}

func TestValidateBroadbandAddressLeaseConfigAllowsDisabledEmptyConfig(t *testing.T) {
	require.NoError(t, validateBroadbandAddressLeaseConfig(BroadbandAddressLeaseConfig{}, BroadbandSubscriberStateConfig{}, BroadbandPPPoEConfig{}, RadiusConfig{}, "lite"))
}

func broadbandAddressLeaseValidationFixture() BroadbandAddressLeaseConfig {
	return BroadbandAddressLeaseConfig{
		Enabled:                       true,
		Mode:                          "enforce",
		FailClosed:                    true,
		StickyIPv4:                    true,
		StickyIPv6:                    true,
		DualStackRequired:             true,
		DelegatedPrefixRequired:       true,
		ReservationRequired:           true,
		ConflictDetectionEnabled:      true,
		AccountingCorrelationRequired: true,
		CoAOnConflict:                 true,
		ReleaseOnAccountingStop:       true,
		Pools: []BroadbandAddressLeasePoolConfig{
			{Name: "pppoe-v4", Family: "ipv4", CIDR: "100.64.0.0/24", Start: "100.64.0.10", End: "100.64.0.250", Gateway: "100.64.0.1", Product: "residential-fiber", Dynamic: true, Sticky: true, VendorPacks: []string{"standard", "aegisnas"}},
		},
		Reservations: []BroadbandAddressLeaseReservationConfig{
			{Key: "lab-cpe-01", SubscriberID: "sub-lab-cpe-01", Product: "residential-fiber", Pool: "pppoe-v4", Family: "ipv4", AssignmentType: "address", Address: "100.64.0.20"},
		},
	}
}

func broadbandAddressLeaseSubscriberFixture() BroadbandSubscriberStateConfig {
	return BroadbandSubscriberStateConfig{
		Enabled:             true,
		DefaultAccessMethod: "pppoe",
		Products: []BroadbandSubscriberProductConfig{
			{Name: "residential-fiber", Enabled: true, Role: "residential", AddressPool: "pppoe-v4", IPv6Pool: "pppoe-v6", DelegatedIPv6Pool: "pppoe-pd"},
		},
	}
}

func broadbandAddressLeaseRadiusFixture() RadiusConfig {
	return RadiusConfig{
		SQLAccounting:      RadiusSQLAccountingConfig{Enabled: true},
		AccountingServices: RadiusAccountingServicesConfig{Enabled: true},
		DynamicAuth:        DynamicAuthConfig{Enabled: true},
		AddressPolicy: RadiusAddressPolicyConfig{
			Enabled: true,
			Pools: []RadiusAddressPoolConfig{
				{Name: "pppoe-v4"},
				{Name: "pppoe-v6"},
				{Name: "pppoe-pd"},
			},
		},
	}
}

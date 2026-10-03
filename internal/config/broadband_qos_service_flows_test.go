package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBroadbandQoSServiceFlowValidation(t *testing.T) {
	cfg := testBroadbandQoSServiceFlowConfig()
	require.NoError(t, validateBroadbandQoSServiceFlowConfig(cfg.Broadband.QoSServiceFlows, cfg.Broadband.Subscriber, cfg.Broadband.CommercialCatalog, cfg.Radius, "enterprise"))

	cfg.Broadband.QoSServiceFlows.Profiles[0].DownloadRateKbps = 0
	require.ErrorContains(t, validateBroadbandQoSServiceFlowConfig(cfg.Broadband.QoSServiceFlows, cfg.Broadband.Subscriber, cfg.Broadband.CommercialCatalog, cfg.Radius, "enterprise"), "download_rate_kbps")

	cfg = testBroadbandQoSServiceFlowConfig()
	cfg.Radius.DynamicAuth.Enabled = false
	require.ErrorContains(t, validateBroadbandQoSServiceFlowConfig(cfg.Broadband.QoSServiceFlows, cfg.Broadband.Subscriber, cfg.Broadband.CommercialCatalog, cfg.Radius, "enterprise"), "coa_on_change")
}

func testBroadbandQoSServiceFlowConfig() *Config {
	return &Config{
		Radius: RadiusConfig{
			SQLAccounting:      RadiusSQLAccountingConfig{Enabled: true},
			AccountingServices: RadiusAccountingServicesConfig{Enabled: true},
			DynamicAuth:        DynamicAuthConfig{Enabled: true},
		},
		Broadband: BroadbandConfig{
			Subscriber: BroadbandSubscriberStateConfig{
				Enabled: true,
				Products: []BroadbandSubscriberProductConfig{
					{Name: "fiber-100m", Enabled: true, Role: "subscriber", QoSProfile: "silver", ServiceChain: "internet"},
				},
			},
			CommercialCatalog: BroadbandCommercialCatalog{Enabled: true},
			QoSServiceFlows: BroadbandQoSServiceFlowConfig{
				Enabled: true,
				Mode:    "enforce",
				Profiles: []BroadbandQoSProfileConfig{
					{Name: "silver", Enabled: true, TrafficClass: "data", DownloadRateKbps: 100000, UploadRateKbps: 20000, DownloadPeakRateKbps: 120000, UploadPeakRateKbps: 25000, Priority: 4, VendorPacks: []string{"mikrotik", "huawei"}},
				},
				ServiceFlows: []BroadbandQoSServiceFlowIntentConfig{
					{Name: "fiber-internet", Enabled: true, Product: "fiber-100m", ServiceLeg: "internet", Direction: "bidirectional", Profile: "silver", VendorPacks: []string{"mikrotik", "huawei"}},
				},
				AggregatePolicies: []BroadbandQoSAggregatePolicyConfig{
					{Name: "tenant-retail", Enabled: true, Scope: "tenant", Profile: "silver", DownloadLimitKbps: 1000000, UploadLimitKbps: 250000},
				},
			},
		},
	}
}

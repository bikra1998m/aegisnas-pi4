package network

import (
	"fmt"
	"sort"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const ApplyConfirmationPhrase = "APPLY EDGE NETWORK"

type ApplyRiskItem struct {
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ApplyRiskAssessment struct {
	RequiresConfirmation bool            `json:"requires_confirmation"`
	ConfirmationPhrase   string          `json:"confirmation_phrase,omitempty"`
	Summary              string          `json:"summary"`
	Items                []ApplyRiskItem `json:"items"`
}

func AssessApplyRisk(cfg *config.Config, current, desired AppliedState) ApplyRiskAssessment {
	diff := DiffState(current, desired)
	assessment := ApplyRiskAssessment{
		Summary: "No risky edge-network changes detected.",
		Items:   []ApplyRiskItem{},
	}

	lanName := strings.TrimSpace(cfg.LAN.Name)
	if lanName != "" {
		currentAddress := interfaceAddressByName(current.Interfaces, lanName)
		desiredAddress := interfaceAddressByName(desired.Interfaces, lanName)
		if currentAddress != desiredAddress && (currentAddress != "" || desiredAddress != "") {
			assessment.addDanger("lan_address_change", fmt.Sprintf("LAN interface %s will move from %s to %s. Downstream client management access may change immediately.", lanName, displayValue(currentAddress), displayValue(desiredAddress)))
		}
	}

	wanName := strings.TrimSpace(cfg.WAN.Name)
	if wanName != "" && !cfg.WAN.DHCP {
		currentAddress := interfaceAddressByName(current.Interfaces, wanName)
		desiredAddress := interfaceAddressByName(desired.Interfaces, wanName)
		if currentAddress != desiredAddress && (currentAddress != "" || desiredAddress != "") {
			assessment.addDanger("wan_address_change", fmt.Sprintf("WAN interface %s will move from %s to %s. Upstream connectivity may drop while the new address is applied.", wanName, displayValue(currentAddress), displayValue(desiredAddress)))
		}
	}

	if !gatewaySetsEqual(current.Gateways, desired.Gateways) && (len(current.Gateways) > 0 || len(desired.Gateways) > 0) {
		assessment.addDanger("default_gateway_change", "Default gateway selection will change. Upstream reachability and remote management may be interrupted until the new gateway is healthy.")
	}

	if len(diff.InterfacesRemoved) > 0 {
		assessment.addWarning("interface_removal", fmt.Sprintf("Managed interface addresses will be removed: %s.", strings.Join(diff.InterfacesRemoved, ", ")))
	}
	if len(diff.GatewaysRemoved) > 0 {
		assessment.addWarning("gateway_removal", fmt.Sprintf("Existing default gateway entries will be removed: %s.", strings.Join(diff.GatewaysRemoved, ", ")))
	}
	if len(diff.RoutesRemoved) > 0 {
		assessment.addWarning("route_removal", fmt.Sprintf("Static routes will be removed: %s.", strings.Join(diff.RoutesRemoved, ", ")))
	}

	if assessment.RequiresConfirmation {
		assessment.ConfirmationPhrase = ApplyConfirmationPhrase
		assessment.Summary = "This edge-network apply changes primary connectivity. Review the warnings and enter the confirmation phrase before applying."
	} else if len(assessment.Items) > 0 {
		assessment.Summary = "Review the network warnings before applying."
	}

	sort.SliceStable(assessment.Items, func(i, j int) bool {
		return assessment.Items[i].Code < assessment.Items[j].Code
	})
	return assessment
}

func (assessment *ApplyRiskAssessment) addDanger(code, message string) {
	assessment.RequiresConfirmation = true
	assessment.Items = append(assessment.Items, ApplyRiskItem{
		Level:   "danger",
		Code:    strings.TrimSpace(code),
		Message: strings.TrimSpace(message),
	})
}

func (assessment *ApplyRiskAssessment) addWarning(code, message string) {
	assessment.Items = append(assessment.Items, ApplyRiskItem{
		Level:   "warning",
		Code:    strings.TrimSpace(code),
		Message: strings.TrimSpace(message),
	})
}

func interfaceAddressByName(items []ManagedInterfaceState, name string) string {
	name = strings.TrimSpace(name)
	for _, item := range items {
		if strings.TrimSpace(item.Name) == name {
			return strings.TrimSpace(item.Address)
		}
	}
	return ""
}

func gatewaySetsEqual(left, right []GatewayState) bool {
	if len(left) != len(right) {
		return false
	}
	leftKeys := make(map[string]struct{}, len(left))
	for _, item := range left {
		leftKeys[item.key()] = struct{}{}
	}
	for _, item := range right {
		if _, ok := leftKeys[item.key()]; !ok {
			return false
		}
	}
	return true
}

func displayValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "not configured"
	}
	return strings.TrimSpace(value)
}

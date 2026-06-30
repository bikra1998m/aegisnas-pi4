package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

const (
	ciscoISEDACLCollection  = "/ers/config/downloadableacl"
	ciscoISEAuthzCollection = "/ers/config/authorizationprofile"
)

type ciscoISEResource struct {
	Kind       string
	Name       string
	Collection string
	Wrapper    string
	Payload    map[string]any
}

type ciscoISEClient struct {
	baseURL   string
	username  string
	password  string
	csrfToken string
	http      *http.Client
}

type ciscoISEResourceSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type ciscoISESearchResponse struct {
	SearchResult struct {
		Total     int                       `json:"total"`
		Resources []ciscoISEResourceSummary `json:"resources"`
	} `json:"SearchResult"`
}

func buildCiscoISEPreviewPayload(cfg *config.Config) map[string]any {
	resources, warnings, err := loadCiscoISEResources(cfg)
	payload := map[string]any{
		"adapter": "cisco-ise-ers",
		"site":    strings.TrimSpace(cfg.Integrations.Controller.Site),
	}
	items := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		items = append(items, map[string]any{
			"kind": resource.Kind, "name": resource.Name, "collection": resource.Collection, "payload": resource.Payload,
		})
	}
	payload["resources"] = items
	if len(warnings) > 0 {
		payload["warnings"] = warnings
	}
	if err != nil {
		payload["load_error"] = err.Error()
	}
	return payload
}

func executeCiscoISEOperation(ctx context.Context, cfg *config.Config, operation string) (*controllerSyncResult, error) {
	username, password, err := ciscoISECredentials(cfg)
	if err != nil {
		return nil, err
	}
	resources, warnings, err := loadCiscoISEResources(cfg)
	if err != nil {
		return nil, err
	}
	jar, _ := cookiejar.New(nil)
	client := &ciscoISEClient{
		baseURL:  strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/"),
		username: username,
		password: password,
		http:     &http.Client{Timeout: 15 * time.Second, Jar: jar},
	}

	desiredItems := make([]map[string]any, 0, len(resources))
	observedItems := make([]map[string]any, 0, len(resources))
	driftItems := make([]string, 0)
	failedDACLs := map[string]struct{}{}
	result := &controllerSyncResult{
		Adapter:          "cisco-ise-ers",
		TargetURL:        client.baseURL + ciscoISEDACLCollection,
		AuthScheme:       "basic",
		ControllerHealth: "healthy",
		WarningCount:     len(warnings),
		ResponseDetails:  map[string]any{"native_api": true, "resource_count": len(resources)},
	}
	if len(resources) == 0 {
		if _, probeErr := client.doJSON(ctx, http.MethodGet, ciscoISEDACLCollection+"?size=1", nil); probeErr != nil {
			result.ControllerHealth = "degraded"
			result.FailedCount = 1
			return result, probeErr
		}
	}
	for _, resource := range resources {
		desiredItems = append(desiredItems, map[string]any{"kind": resource.Kind, "name": resource.Name, "payload": resource.Payload})
		if operation == "push" && resource.Kind == "authorization_profile" {
			if daclName := ciscoISEProfileDACLName(resource.Payload); daclName != "" {
				if _, failed := failedDACLs[daclName]; failed {
					result.FailedCount++
					driftItems = append(driftItems, resource.Kind+":"+resource.Name+":dependency-failed")
					continue
				}
			}
		}
		id, found, findErr := client.findByName(ctx, resource.Collection, resource.Name)
		if findErr != nil {
			result.FailedCount++
			if resource.Kind == "downloadable_acl" {
				failedDACLs[resource.Name] = struct{}{}
			}
			driftItems = append(driftItems, resource.Kind+":"+resource.Name+":lookup-failed")
			continue
		}
		if !found {
			driftItems = append(driftItems, resource.Kind+":"+resource.Name+":missing")
			observedItems = append(observedItems, map[string]any{"kind": resource.Kind, "name": resource.Name, "state": "missing"})
			if operation == "push" {
				if _, createErr := client.doJSON(ctx, http.MethodPost, resource.Collection, resource.Payload); createErr != nil {
					result.FailedCount++
					if resource.Kind == "downloadable_acl" {
						failedDACLs[resource.Name] = struct{}{}
					}
					continue
				}
				result.AppliedCount++
			}
			continue
		}

		body, detailErr := client.doJSON(ctx, http.MethodGet, resource.Collection+"/"+url.PathEscape(id), nil)
		if detailErr != nil {
			result.FailedCount++
			if resource.Kind == "downloadable_acl" {
				failedDACLs[resource.Name] = struct{}{}
			}
			driftItems = append(driftItems, resource.Kind+":"+resource.Name+":read-failed")
			continue
		}
		observed := ciscoISEWrappedResource(body, resource.Wrapper)
		projected := projectControllerState(observed, resource.Payload[resource.Wrapper])
		observedItems = append(observedItems, map[string]any{"kind": resource.Kind, "name": resource.Name, "payload": map[string]any{resource.Wrapper: projected}})
		if controllerDesiredStateHash(map[string]any{"value": projected}) == controllerDesiredStateHash(map[string]any{"value": resource.Payload[resource.Wrapper]}) {
			continue
		}
		driftItems = append(driftItems, resource.Kind+":"+resource.Name+":changed")
		if operation == "push" {
			if _, updateErr := client.doJSON(ctx, http.MethodPut, resource.Collection+"/"+url.PathEscape(id), resource.Payload); updateErr != nil {
				result.FailedCount++
				if resource.Kind == "downloadable_acl" {
					failedDACLs[resource.Name] = struct{}{}
				}
				continue
			}
			result.AppliedCount++
		}
	}

	desiredState := map[string]any{"resources": desiredItems}
	observedState := map[string]any{"resources": observedItems}
	result.DesiredStateHash = controllerDesiredStateHash(desiredState)
	result.ObservedStateHash = controllerDesiredStateHash(observedState)
	result.DriftCount = len(driftItems)
	result.DriftDetected = result.DriftCount > 0
	result.CompatibilityScore = 100
	if len(warnings) > 0 {
		result.CompatibilityScore = 95
		result.ResponseDetails["response_warnings"] = warnings
	}
	if len(driftItems) > 0 {
		result.ResponseDetails["drift_items"] = driftItems
	}
	if operation == "push" && result.FailedCount == 0 {
		result.DriftDetected = false
		result.DriftCount = 0
		result.ObservedStateHash = result.DesiredStateHash
		result.ResponseDetails["remediated_count"] = len(driftItems)
		result.ResponseSummary = fmt.Sprintf("Cisco ISE ERS reconciliation applied %d resource(s).", result.AppliedCount)
	} else if operation == "pull" {
		result.ResponseSummary = fmt.Sprintf("Cisco ISE ERS inspection found %d drift item(s).", result.DriftCount)
	}
	result.ResponseStatus = "200 " + http.StatusText(http.StatusOK)
	if result.FailedCount > 0 {
		result.ControllerHealth = "degraded"
		return result, fmt.Errorf("Cisco ISE ERS operation failed for %d resource(s)", result.FailedCount)
	}
	return result, nil
}

func ciscoISEProfileDACLName(payload map[string]any) string {
	profile, _ := payload["AuthorizationProfile"].(map[string]any)
	name, _ := profile["daclName"].(string)
	return strings.TrimSpace(name)
}

func ciscoISECredentials(cfg *config.Config) (string, string, error) {
	if cfg == nil {
		return "", "", fmt.Errorf("controller config is required")
	}
	usernameEnv := strings.TrimSpace(cfg.Integrations.Controller.APIUsernameEnv)
	passwordEnv := strings.TrimSpace(cfg.Integrations.Controller.APIPasswordEnv)
	username := strings.TrimSpace(os.Getenv(usernameEnv))
	password := os.Getenv(passwordEnv)
	if usernameEnv == "" || passwordEnv == "" {
		return "", "", fmt.Errorf("Cisco ISE requires integrations.controller.api_username_env and api_password_env")
	}
	if username == "" || password == "" {
		return "", "", fmt.Errorf("Cisco ISE credential environment variables %q and %q must both be present", usernameEnv, passwordEnv)
	}
	return username, password, nil
}

func (c *ciscoISEClient) findByName(ctx context.Context, collection, name string) (string, bool, error) {
	query := url.Values{}
	query.Set("filter", "name.EQ."+name)
	query.Set("size", "100")
	body, err := c.doJSON(ctx, http.MethodGet, collection+"?"+query.Encode(), nil)
	if err != nil {
		return "", false, err
	}
	var search ciscoISESearchResponse
	if err := json.Unmarshal(body, &search); err != nil {
		return "", false, fmt.Errorf("decode Cisco ISE search response: %w", err)
	}
	for _, resource := range search.SearchResult.Resources {
		if resource.Name == name {
			return resource.ID, true, nil
		}
	}
	return "", false, nil
}

func (c *ciscoISEClient) doJSON(ctx context.Context, method, path string, payload map[string]any) ([]byte, error) {
	var bodyReader *strings.Reader
	if payload == nil {
		bodyReader = strings.NewReader("")
	} else {
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		bodyReader = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if method == http.MethodGet && c.csrfToken == "" {
		req.Header.Set("X-CSRF-TOKEN", "Fetch")
	} else if c.csrfToken != "" {
		req.Header.Set("X-CSRF-TOKEN", c.csrfToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if token := strings.TrimSpace(resp.Header.Get("X-CSRF-TOKEN")); token != "" && !strings.EqualFold(token, "Fetch") {
		c.csrfToken = token
	}
	body, err := ioReadAllLimit(resp, 4<<20)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, fmt.Errorf("Cisco ISE ERS %s %s returned %s: %s", method, path, resp.Status, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func loadCiscoISEResources(cfg *config.Config) ([]ciscoISEResource, []string, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("controller config is required")
	}
	if db.DB == nil {
		return nil, nil, nil
	}
	prefix := ciscoISEManagedPrefix(cfg.Integrations.Controller.Site)
	aclNames := map[string]string{}
	var resources []ciscoISEResource
	var warnings []string
	rows, err := db.DB.Query(`SELECT name, COALESCE(description, ''), rules_json FROM acl_policies WHERE enabled = 1 ORDER BY name`)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var name, description, rulesJSON string
		if err := rows.Scan(&name, &description, &rulesJSON); err != nil {
			rows.Close()
			return nil, nil, err
		}
		var rules []radius.ACLRule
		if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("decode ACL policy %q: %w", name, err)
		}
		lines, omitted, err := radius.RenderCiscoDownloadableACL(rules)
		if err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("render ACL policy %q: %w", name, err)
		}
		if omitted > 0 {
			warnings = append(warnings, fmt.Sprintf("ACL policy %s omitted %d outbound rule(s) from the Cisco session DACL.", name, omitted))
		}
		if len(lines) == 0 {
			warnings = append(warnings, fmt.Sprintf("ACL policy %s has no inbound rules and was not exported as a Cisco DACL.", name))
			continue
		}
		managedName := ciscoISEObjectName(prefix, name)
		aclNames[name] = managedName
		resources = append(resources, ciscoISEResource{
			Kind: "downloadable_acl", Name: managedName, Collection: ciscoISEDACLCollection, Wrapper: "DownloadableAcl",
			Payload: map[string]any{"DownloadableAcl": map[string]any{
				"name": managedName, "description": ciscoISEDescription(description, cfg.Integrations.Controller.Site),
				"dacl": strings.Join(lines, "\n"), "daclType": "IPV4",
			}},
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, err
	}
	rows.Close()

	roleRows, err := db.DB.Query(`SELECT name, COALESCE(description, ''), COALESCE(vlan, 0), COALESCE(acl_policy_name, '') FROM roles ORDER BY name`)
	if err != nil {
		return nil, nil, err
	}
	for roleRows.Next() {
		var name, description, aclPolicy string
		var vlan int
		if err := roleRows.Scan(&name, &description, &vlan, &aclPolicy); err != nil {
			roleRows.Close()
			return nil, nil, err
		}
		managedName := ciscoISEObjectName(prefix, name)
		profile := map[string]any{
			"name": managedName, "description": ciscoISEDescription(description, cfg.Integrations.Controller.Site),
			"accessType": "ACCESS_ACCEPT", "authzProfileType": "SWITCH", "profileName": "Cisco",
		}
		if vlan > 0 {
			profile["vlan"] = map[string]any{"nameID": strconv.Itoa(vlan), "tagID": 0}
		}
		if daclName := aclNames[aclPolicy]; daclName != "" {
			profile["daclName"] = daclName
		} else if aclPolicy != "" {
			warnings = append(warnings, fmt.Sprintf("Role %s references ACL policy %s, which has no Cisco DACL export.", name, aclPolicy))
		}
		resources = append(resources, ciscoISEResource{
			Kind: "authorization_profile", Name: managedName, Collection: ciscoISEAuthzCollection, Wrapper: "AuthorizationProfile",
			Payload: map[string]any{"AuthorizationProfile": profile},
		})
	}
	if err := roleRows.Err(); err != nil {
		roleRows.Close()
		return nil, nil, err
	}
	roleRows.Close()
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Kind == resources[j].Kind {
			return resources[i].Name < resources[j].Name
		}
		return ciscoISEResourceRank(resources[i].Kind) < ciscoISEResourceRank(resources[j].Kind)
	})
	return resources, warnings, nil
}

func ciscoISEResourceRank(kind string) int {
	if kind == "downloadable_acl" {
		return 0
	}
	return 1
}

func ciscoISEManagedPrefix(site string) string {
	site = sanitizeCiscoISEName(site)
	if site == "" {
		return "aegisnas"
	}
	return "aegisnas-" + site
}

func ciscoISEObjectName(prefix, name string) string {
	value := sanitizeCiscoISEName(prefix + "-" + name)
	if len(value) <= 64 {
		return value
	}
	digest := sha256.Sum256([]byte(value))
	return strings.TrimRight(value[:51], "-_.") + "-" + hex.EncodeToString(digest[:6])
}

func sanitizeCiscoISEName(value string) string {
	value = strings.TrimSpace(value)
	var out strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9', char == '_', char == '.', char == '-':
			out.WriteRune(char)
		default:
			out.WriteByte('-')
		}
	}
	return strings.Trim(out.String(), "-_.")
}

func ciscoISEDescription(description, site string) string {
	prefix := "Managed by AegisNAS"
	if strings.TrimSpace(site) != "" {
		prefix += " for " + strings.TrimSpace(site)
	}
	if strings.TrimSpace(description) == "" {
		return prefix
	}
	return prefix + ". " + strings.TrimSpace(description)
}

func ciscoISEWrappedResource(body []byte, wrapper string) map[string]any {
	var payload map[string]any
	if json.Unmarshal(body, &payload) != nil {
		return nil
	}
	resource, _ := payload[wrapper].(map[string]any)
	return resource
}

func projectControllerState(observed, desired any) any {
	switch expected := desired.(type) {
	case map[string]any:
		actual, _ := observed.(map[string]any)
		projected := make(map[string]any, len(expected))
		for key, expectedValue := range expected {
			projected[key] = projectControllerState(actual[key], expectedValue)
		}
		return projected
	case []map[string]any:
		actual, _ := observed.([]any)
		projected := make([]any, 0, len(expected))
		for index, expectedValue := range expected {
			if index < len(actual) {
				projected = append(projected, projectControllerState(actual[index], expectedValue))
			} else {
				projected = append(projected, nil)
			}
		}
		return projected
	case []any:
		actual, _ := observed.([]any)
		projected := make([]any, 0, len(expected))
		for index, expectedValue := range expected {
			if index < len(actual) {
				projected = append(projected, projectControllerState(actual[index], expectedValue))
			} else {
				projected = append(projected, nil)
			}
		}
		return projected
	default:
		return observed
	}
}

func ioReadAllLimit(resp *http.Response, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("controller response exceeds %d bytes", limit)
	}
	return body, nil
}

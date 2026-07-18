package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func HandleGetOpenAPI(w http.ResponseWriter, r *http.Request) {
	spec := buildOpenAPISpec(r, config.Get())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="aegisnas-admin-api-openapi.json"`)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(spec)
}

func buildOpenAPISpec(r *http.Request, cfg *config.Config) map[string]any {
	paths := map[string]any{}

	addOperation(paths, "/health", "get", openAPIOperation("Health probe", "Health", nil, map[string]any{
		"200":     responseJSON("Health status payload."),
		"default": responseText("Unexpected error."),
	}))
	addOperation(paths, "/api/v1/openapi.json", "get", openAPIOperation("Download OpenAPI schema", "Documentation", nil, map[string]any{
		"200": responseJSON("OpenAPI 3.1 schema for the admin API."),
	}))
	addOperation(paths, "/api/v1/auth/options", "get", openAPIOperation("List admin authentication options", "Authentication", nil, map[string]any{
		"200": responseJSON("Available admin login methods and runtime support."),
	}))
	addOperation(paths, "/api/v1/auth/token/start", "post", openAPIOperationWithBody("Start token or passkey admin login", "Authentication", genericJSONObjectRequest("Bearer token first factor."), map[string]any{
		"200": responseJSON("Either a completed token login or a WebAuthn request-options challenge."),
		"401": responseJSON("Invalid or expired token."),
		"403": responseJSON("Passkey step-up is required but cannot be started."),
	}))
	addOperation(paths, "/api/v1/auth/webauthn/login/options", "post", openAPIOperationWithBody("Fetch pending passkey login options", "Authentication", genericJSONObjectRequest("Pending WebAuthn state from SSO redirect or token start."), map[string]any{
		"200":     responseJSON("WebAuthn PublicKeyCredentialRequestOptions for the pending state."),
		"default": responseJSON("Pending challenge lookup error."),
	}))
	addOperation(paths, "/api/v1/auth/webauthn/login/finish", "post", openAPIOperationWithBody("Finish passkey admin login", "Authentication", genericJSONObjectRequest("Pending state and browser assertion credential."), map[string]any{
		"200":     responseJSON("Short-lived verified admin session token."),
		"403":     responseJSON("Passkey assertion denied."),
		"default": responseJSON("Passkey verification error."),
	}))
	addOperation(paths, "/api/v1/auth/sso/start", "get", openAPIOperation("Start admin SSO flow", "Authentication", nil, map[string]any{
		"200":     responseJSON("SSO start details or redirect metadata."),
		"default": responseText("Authentication error."),
	}))
	addOperation(paths, "/api/v1/auth/sso/metadata", "get", openAPIOperation("Download SAML metadata", "Authentication", nil, map[string]any{
		"200":     responseXML("Admin SSO SAML metadata when SAML is enabled."),
		"default": responseText("Metadata is unavailable."),
	}))
	addOperation(paths, "/api/v1/nas/enroll", "post", openAPIOperation("Bootstrap dynamic NAS enrollment", "RADIUS", nil, map[string]any{
		"201":     responseJSON("Auto-approved dynamic NAS enrollment when approval_required is false and credentials validate."),
		"202":     responseJSON("Pending dynamic NAS enrollment awaiting administrator approval."),
		"401":     responseText("Missing or invalid enrollment token."),
		"default": responseText("Enrollment validation error."),
	}))
	addOperation(paths, "/api/v1/auth/validate", "get", securedOperation("Validate admin token", "Authentication", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Resolved admin identity and role scopes."),
		"401": responseText("Missing or invalid token."),
	}))
	addOperation(paths, "/api/v1/auth/logout", "post", securedOperation("Invalidate current admin session", "Authentication", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Logout result."),
		"401": responseText("Missing or invalid token."),
	}))

	addOperation(paths, "/api/v1/system/status", "get", securedOperation("Read system runtime status", "System", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Service health, integration state, HA state, runtime counters, and deployment scaling status."),
	}))
	addOperation(paths, "/api/v1/system/settings", "get", securedOperation("Read effective system settings", "System", []string{"super_admin"}, map[string]any{
		"200": responseJSON("Current system settings payload."),
	}))
	addOperation(paths, "/api/v1/system/settings", "put", securedOperationWithBody("Update system settings", "System", []string{"super_admin"}, genericJSONObjectRequest("New settings payload to persist."), map[string]any{
		"200":     responseJSON("Saved settings payload."),
		"default": responseText("Validation or persistence error."),
	}))
	addOperation(paths, "/api/v1/system/settings/evaluate", "post", securedOperationWithBody("Evaluate draft system settings", "System", []string{"super_admin"}, genericJSONObjectRequest("Draft settings payload to evaluate without saving."), map[string]any{
		"200":     responseJSON("Capability, hardware scaling, and validation preview for the draft settings."),
		"default": responseText("Draft evaluation error."),
	}))
	addOperation(paths, "/api/v1/system/settings/export", "get", securedOperation("Export system settings", "System", []string{"super_admin"}, map[string]any{
		"200": responseBinary("application/json", "Exported system settings JSON."),
	}))
	addOperation(paths, "/api/v1/system/settings/import", "post", securedOperationWithBody("Import system settings", "System", []string{"super_admin"}, genericJSONObjectRequest("System settings payload to import."), map[string]any{
		"200":     responseJSON("Import result."),
		"default": responseText("Import validation error."),
	}))
	addOperation(paths, "/api/v1/system/support-bundle/summary", "get", securedOperation("Preview support bundle contents", "System", []string{"ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Support bundle capture summary, redaction notes, and included diagnostics."),
	}))
	addOperation(paths, "/api/v1/system/support-bundle", "get", securedOperation("Download support bundle", "System", []string{"ops_admin", "super_admin"}, map[string]any{
		"200": responseBinary("application/zip", "Support bundle zip with redacted settings and diagnostics."),
	}))
	addOperation(paths, "/api/v1/system/support-bundle-exports", "get", securedOperation("List scheduled support bundle exports", "System", []string{"ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled support bundle export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/support-bundle-exports/download", "get", securedOperationWithParameters("Download scheduled support bundle export", "System", []string{"ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Support bundle export artifact filename.", true),
	}, map[string]any{
		"200": responseBinary("application/zip", "Scheduled support bundle export zip artifact."),
	}))
	addOperation(paths, "/api/v1/system/upgrade-readiness", "get", securedOperation("Assess upgrade readiness", "Upgrade", []string{"ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Upgrade readiness report with migration rehearsal details."),
	}))
	addOperation(paths, "/api/v1/system/upgrade-readiness-exports", "get", securedOperation("List scheduled upgrade readiness exports", "Upgrade", []string{"ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled upgrade readiness export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/upgrade-readiness-exports/download", "get", securedOperationWithParameters("Download scheduled upgrade readiness export", "Upgrade", []string{"ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Upgrade readiness export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled upgrade readiness export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/upgrade-rollback-package", "get", securedOperation("Download upgrade rollback package", "Upgrade", []string{"ops_admin", "super_admin"}, map[string]any{
		"200": responseBinary("application/zip", "Version-aware rollback package containing config and SQLite snapshot."),
	}))
	addOperation(paths, "/api/v1/system/upgrade-rollback-package/inspect", "post", securedOperationWithBody("Inspect upgrade rollback package", "Upgrade", []string{"ops_admin", "super_admin"}, multipartRequestBody(
		map[string]any{
			"package": map[string]any{"type": "string", "format": "binary", "description": "Rollback package zip."},
		},
		[]string{"package"},
		"Rollback package to inspect.",
	), map[string]any{
		"200":     responseJSON("Rollback package compatibility inspection."),
		"default": responseText("Inspection error."),
	}))
	addOperation(paths, "/api/v1/system/upgrade-rollback-package/restore", "post", securedOperationWithBody("Restore upgrade rollback package online", "Upgrade", []string{"ops_admin", "super_admin"}, multipartRequestBody(
		map[string]any{
			"package":           map[string]any{"type": "string", "format": "binary", "description": "Rollback package zip."},
			"confirmation_text": map[string]any{"type": "string", "description": "Typed confirmation text required by the runtime."},
		},
		[]string{"package", "confirmation_text"},
		"Rollback package and confirmation text.",
	), map[string]any{
		"200":     responseJSON("Rollback restore result including safety package path."),
		"default": responseText("Restore error or compatibility failure."),
	}))

	addOperation(paths, "/api/v1/system/dhcp-leases", "get", securedOperation("List live DHCP leases", "Network", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Current DHCP lease table."),
	}))
	addOperation(paths, "/api/v1/system/dhcp-lease-history", "get", securedOperation("List DHCP lease history", "Network", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Stored DHCP lease observations."),
	}))
	addOperation(paths, "/api/v1/system/dhcp-lease-history/export", "get", securedOperation("Export DHCP lease history", "Network", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseBinary("text/csv", "DHCP lease history export."),
	}))
	addOperation(paths, "/api/v1/system/session-history", "get", securedOperationWithParameters("List session and accounting history", "Sessions", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("username", "Optional exact username filter.", false),
		queryStringParameter("auth_method", "Optional exact authentication method filter.", false),
		queryStringParameter("active", "Optional active-state filter using true or false.", false),
		queryStringParameter("limit", "Optional record limit. Defaults to 200 and caps at 5000.", false),
	}, map[string]any{
		"200": responseJSON("Durable session and accounting history with traffic and duration counters."),
	}))
	addOperation(paths, "/api/v1/system/session-history/export", "get", securedOperationWithParameters("Export session and accounting history", "Sessions", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("username", "Optional exact username filter.", false),
		queryStringParameter("auth_method", "Optional exact authentication method filter.", false),
		queryStringParameter("active", "Optional active-state filter using true or false.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Session and accounting history export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/session-analytics", "get", securedOperationWithParameters("Summarize session and accounting activity trends", "Sessions", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("username", "Optional exact username filter.", false),
		queryStringParameter("auth_method", "Optional exact authentication method filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": responseJSON("Session activity summary with auth, role, VLAN, concurrency, and bucketed trend counters."),
	}))
	addOperation(paths, "/api/v1/system/session-analytics/export", "get", securedOperationWithParameters("Export session activity analytics", "Sessions", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("username", "Optional exact username filter.", false),
		queryStringParameter("auth_method", "Optional exact authentication method filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Session activity analytics export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/voucher-analytics", "get", securedOperationWithParameters("Summarize voucher inventory, usage, and expiry trends", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 720.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 30 and caps at 90.", false),
	}, map[string]any{
		"200": responseJSON("Voucher activity summary with active, exhausted, expired, utilization, role, state, and bucketed creation counters."),
	}))
	addOperation(paths, "/api/v1/system/voucher-analytics/export", "get", securedOperationWithParameters("Export voucher inventory and usage analytics", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 720.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 30 and caps at 90.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Voucher analytics export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/voucher-aging-analytics", "get", securedOperationWithParameters("Summarize voucher stock aging and stale inventory", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("window_hours", "Optional backward-looking aging horizon in hours. Defaults to 720.", false),
		queryStringParameter("bucket_count", "Optional aging bucket count. Defaults to 30 and caps at 90.", false),
	}, map[string]any{
		"200": responseJSON("Voucher stock aging summary with stale inventory counts, unused backlog age, older role mix, and age-band buckets."),
	}))
	addOperation(paths, "/api/v1/system/voucher-aging-analytics/export", "get", securedOperationWithParameters("Export voucher stock aging analytics", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("window_hours", "Optional backward-looking aging horizon in hours. Defaults to 720.", false),
		queryStringParameter("bucket_count", "Optional aging bucket count. Defaults to 30 and caps at 90.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Voucher stock aging analytics export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/voucher-redemption-analytics", "get", securedOperationWithParameters("Summarize voucher redemption behavior and delay trends", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 720.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 30 and caps at 90.", false),
	}, map[string]any{
		"200": responseJSON("Voucher redemption summary with unique redeemed vouchers, first-use delay, active voucher sessions, role mix, and bucketed redemption counters."),
	}))
	addOperation(paths, "/api/v1/system/voucher-redemption-analytics/export", "get", securedOperationWithParameters("Export voucher redemption analytics", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 720.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 30 and caps at 90.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Voucher redemption analytics export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/voucher-expiry-analytics", "get", securedOperationWithParameters("Summarize voucher expiry pressure and at-risk vouchers", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("window_hours", "Optional forward-looking expiry horizon in hours. Defaults to 720.", false),
		queryStringParameter("bucket_count", "Optional expiry bucket count. Defaults to 30 and caps at 90.", false),
	}, map[string]any{
		"200": responseJSON("Voucher expiry pressure, at-risk unused vouchers, operational state mix, and upcoming expiry buckets."),
	}))
	addOperation(paths, "/api/v1/system/voucher-expiry-analytics/export", "get", securedOperationWithParameters("Export voucher expiry analytics", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("window_hours", "Optional forward-looking expiry horizon in hours. Defaults to 720.", false),
		queryStringParameter("bucket_count", "Optional expiry bucket count. Defaults to 30 and caps at 90.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Voucher expiry analytics export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/voucher-redemption-analytics-exports", "get", securedOperation("List scheduled voucher redemption analytics exports", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled voucher redemption analytics export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/voucher-redemption-analytics-exports/download", "get", securedOperationWithParameters("Download scheduled voucher redemption analytics export", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Voucher redemption analytics export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled voucher redemption analytics export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/voucher-expiry-analytics-exports", "get", securedOperation("List scheduled voucher expiry analytics exports", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled voucher expiry analytics export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/voucher-expiry-analytics-exports/download", "get", securedOperationWithParameters("Download scheduled voucher expiry analytics export", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Voucher expiry analytics export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Voucher expiry analytics export artifact.",
			"content": map[string]any{
				"application/json": map[string]any{},
				"text/csv":         map[string]any{},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/voucher-analytics-exports", "get", securedOperation("List scheduled voucher analytics exports", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled voucher analytics export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/voucher-analytics-exports/download", "get", securedOperationWithParameters("Download scheduled voucher analytics export", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Voucher analytics export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled voucher analytics export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/voucher-aging-analytics-exports", "get", securedOperation("List scheduled voucher aging analytics exports", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled voucher aging analytics export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/voucher-aging-analytics-exports/download", "get", securedOperationWithParameters("Download scheduled voucher aging analytics export", "Vouchers", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Voucher aging analytics export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled voucher aging analytics export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/guest-lifecycle", "get", securedOperationWithParameters("Summarize guest access lifecycle activity", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("limit", "Optional guest history row limit. Defaults to 200.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": responseJSON("Guest lifecycle summary with pending, approved, rejected, completed, delivery, and bucketed trend counters."),
	}))
	addOperation(paths, "/api/v1/system/guest-lifecycle/export", "get", securedOperationWithParameters("Export guest lifecycle activity", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("limit", "Optional guest history row limit. Defaults to 5000.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Guest lifecycle export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/guest-delivery-analytics", "get", securedOperationWithParameters("Summarize guest delivery and sponsor approval flow", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": responseJSON("Guest delivery analytics with sponsor backlog, delivery-state mixes, timing metrics, and bucketed approval/invite trends."),
	}))
	addOperation(paths, "/api/v1/system/guest-rejection-analytics", "get", securedOperationWithParameters("Summarize guest rejection reasons and timing", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": responseJSON("Guest rejection analytics with reason, sponsor, company, and timing breakdowns."),
	}))
	addOperation(paths, "/api/v1/system/guest-rejection-analytics/export", "get", securedOperationWithParameters("Export guest rejection analytics", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Guest rejection analytics export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/guest-conversion-analytics", "get", securedOperationWithParameters("Summarize guest conversion funnel and drop-off points", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": responseJSON("Guest conversion analytics with submit, approval, invite, completion, and drop-off timing metrics."),
	}))
	addOperation(paths, "/api/v1/system/guest-conversion-analytics/export", "get", securedOperationWithParameters("Export guest conversion analytics", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Guest conversion analytics export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/guest-conversion-analytics-exports", "get", securedOperation("List scheduled guest conversion analytics exports", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled guest conversion analytics export artifacts and runtime state."),
	}))
	addOperation(paths, "/api/v1/system/guest-conversion-analytics-exports/download", "get", securedOperationWithParameters("Download scheduled guest conversion analytics export", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Scheduled guest conversion analytics export artifact filename.", true),
	}, map[string]any{
		"200": responseBinary("application/octet-stream", "Scheduled guest conversion analytics export content."),
	}))
	addOperation(paths, "/api/v1/system/guest-rejection-analytics-exports", "get", securedOperation("List scheduled guest rejection analytics exports", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled guest rejection analytics export artifacts and runtime state."),
	}))
	addOperation(paths, "/api/v1/system/guest-rejection-analytics-exports/download", "get", securedOperationWithParameters("Download scheduled guest rejection analytics export", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Scheduled guest rejection analytics export artifact filename.", true),
	}, map[string]any{
		"200": responseBinary("application/octet-stream", "Scheduled guest rejection analytics export content."),
	}))
	addOperation(paths, "/api/v1/system/guest-invite-analytics", "get", securedOperationWithParameters("Summarize guest invite throughput and completion timing", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": responseJSON("Guest invite analytics with queued, sent, failed, and post-invite completion timing."),
	}))
	addOperation(paths, "/api/v1/system/guest-invite-analytics/export", "get", securedOperationWithParameters("Export guest invite analytics", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Guest invite analytics export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/guest-invite-analytics-exports", "get", securedOperation("List scheduled guest invite analytics exports", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled guest invite analytics export runtime and artifacts."),
	}))
	addOperation(paths, "/api/v1/system/guest-invite-analytics-exports/download", "get", securedOperationWithParameters("Download scheduled guest invite analytics export", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Scheduled guest invite analytics export filename.", true),
	}, map[string]any{
		"200": responseBinary("application/octet-stream", "Scheduled guest invite analytics export content."),
	}))
	addOperation(paths, "/api/v1/system/guest-delivery-analytics/export", "get", securedOperationWithParameters("Export guest delivery analytics", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Guest delivery analytics export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/guest-delivery-failures", "get", securedOperationWithParameters("Summarize guest delivery failures and queue hotspots", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": responseJSON("Guest delivery failure analytics with top approval and invite errors, queue age, and sponsor or company hotspots."),
	}))
	addOperation(paths, "/api/v1/system/guest-delivery-failures/export", "get", securedOperationWithParameters("Export guest delivery failure analytics", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Guest delivery failure analytics export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/guest-sponsor-analytics", "get", securedOperationWithParameters("Summarize sponsor approval backlog and response timing", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": responseJSON("Sponsor approval analytics with backlog aging, top sponsors, approval timing, and bucketed sponsor-response trends."),
	}))
	addOperation(paths, "/api/v1/system/guest-sponsor-analytics/export", "get", securedOperationWithParameters("Export sponsor approval analytics", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("status", "Optional guest status filter.", false),
		queryStringParameter("window_hours", "Optional analytics window in hours. Defaults to 24.", false),
		queryStringParameter("bucket_count", "Optional trend bucket count. Defaults to 24 and caps at 96.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Sponsor approval analytics export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/guest-delivery-analytics-exports", "get", securedOperation("List scheduled guest delivery analytics exports", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled guest delivery analytics export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/guest-delivery-analytics-exports/download", "get", securedOperationWithParameters("Download scheduled guest delivery analytics export", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Guest delivery analytics export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled guest delivery analytics export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/guest-delivery-failures-exports", "get", securedOperation("List scheduled guest delivery failure exports", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled guest delivery failure export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/guest-delivery-failures-exports/download", "get", securedOperationWithParameters("Download scheduled guest delivery failure export", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Guest delivery failure export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled guest delivery failure export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/guest-sponsor-analytics-exports", "get", securedOperation("List scheduled guest sponsor analytics exports", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled guest sponsor analytics export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/guest-sponsor-analytics-exports/download", "get", securedOperationWithParameters("Download scheduled guest sponsor analytics export", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Guest sponsor analytics export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled guest sponsor analytics export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/guest-lifecycle-exports", "get", securedOperation("List scheduled guest lifecycle exports", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled guest lifecycle export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/guest-lifecycle-exports/download", "get", securedOperationWithParameters("Download scheduled guest lifecycle export", "Guest", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Guest lifecycle export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled guest lifecycle export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/session-analytics-exports", "get", securedOperation("List scheduled session analytics exports", "Sessions", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled session analytics export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/session-analytics-exports/download", "get", securedOperationWithParameters("Download scheduled session analytics export", "Sessions", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Session analytics export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled session analytics export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/session-exports", "get", securedOperation("List scheduled session exports", "Sessions", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled session export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/session-exports/download", "get", securedOperationWithParameters("Download scheduled session export", "Sessions", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Session export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled session export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/upstream-aaa-history", "get", securedOperationWithParameters("List upstream AAA probe history", "AAA", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("server", "Optional exact upstream server name filter.", false),
		queryStringParameter("status", "Optional status filter such as ok, degraded, down, or disabled.", false),
		queryStringParameter("limit", "Optional record limit. Defaults to 200 and caps at 5000.", false),
	}, map[string]any{
		"200": responseJSON("Durable upstream AAA probe history with aggregate status counters."),
	}))
	addOperation(paths, "/api/v1/system/upstream-aaa-history/export", "get", securedOperationWithParameters("Export upstream AAA probe history", "AAA", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("server", "Optional exact upstream server name filter.", false),
		queryStringParameter("status", "Optional status filter such as ok, degraded, down, or disabled.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Upstream AAA probe history export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/upstream-aaa-exports", "get", securedOperation("List scheduled upstream AAA exports", "AAA", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled upstream AAA export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/upstream-aaa-exports/download", "get", securedOperationWithParameters("Download scheduled upstream AAA export", "AAA", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Upstream AAA export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled upstream AAA export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/audit-history", "get", securedOperationWithParameters("List audit history", "System", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("user", "Optional exact user filter.", false),
		queryStringParameter("action_prefix", "Optional action prefix filter such as download_ or guest_.", false),
		queryStringParameter("limit", "Optional record limit. Defaults to 200 and caps at 5000.", false),
	}, map[string]any{
		"200": responseJSON("Durable audit history records with aggregate counts for exports, staged changes, network, HA, upgrade, and guest actions."),
	}))
	addOperation(paths, "/api/v1/system/audit-history/export", "get", securedOperationWithParameters("Export audit history", "System", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("user", "Optional exact user filter.", false),
		queryStringParameter("action_prefix", "Optional action prefix filter such as download_ or guest_.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Audit history export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/audit-exports", "get", securedOperation("List scheduled audit exports", "System", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled audit export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/audit-exports/download", "get", securedOperationWithParameters("Download scheduled audit export", "System", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Audit export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled audit export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/integration-history", "get", securedOperationWithParameters("List integration automation history", "Integrations", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("component", "Optional component filter such as controller_automation, mdm_sync, or posture_checks.", false),
		queryStringParameter("limit", "Optional record limit. Defaults to 200 and caps at 2000.", false),
	}, map[string]any{
		"200": responseJSON("Durable integration history records with aggregate counters for controller, MDM, and posture automation."),
	}))
	addOperation(paths, "/api/v1/system/integration-history/export", "get", securedOperationWithParameters("Export integration automation history", "Integrations", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
		queryStringParameter("component", "Optional component filter such as controller_automation, mdm_sync, or posture_checks.", false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Integration history export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/integration-exports", "get", securedOperation("List scheduled integration exports", "Integrations", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled integration export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/integration-exports/download", "get", securedOperationWithParameters("Download scheduled integration export", "Integrations", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Integration export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled integration export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/network-preview", "get", securedOperation("Preview managed network changes", "Network", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Generated preview, risk summary, and validation details for managed network state."),
	}))
	addOperation(paths, "/api/v1/system/network-backups", "get", securedOperation("List managed network snapshots", "Network", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Available rollback snapshots for managed network state."),
	}))
	addOperation(paths, "/api/v1/system/network-apply-history", "get", securedOperation("List network apply history", "Network", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Network apply and rollback history entries."),
	}))
	addOperation(paths, "/api/v1/system/network-apply-history/export", "get", securedOperation("Export network apply history", "Network", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseBinary("text/csv", "Network apply history export."),
	}))
	addOperation(paths, "/api/v1/system/network-observability", "get", securedOperation("Read network observability summary", "Network", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Network observability counters, trends, and recovery state."),
	}))
	addOperation(paths, "/api/v1/system/network-exports", "get", securedOperation("List scheduled network exports", "Network", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled network export runtime status and recent artifact list for apply and DHCP lease history."),
	}))
	addOperation(paths, "/api/v1/system/network-exports/download", "get", securedOperationWithParameters("Download scheduled network export", "Network", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Network export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled network export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/diagnostics-report", "get", securedOperation("Read diagnostics report", "System", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Cross-domain diagnostics report with session, network, HA, upgrade, integration, runtime status, and history summary data."),
	}))
	addOperation(paths, "/api/v1/system/diagnostics-report/export", "get", securedOperationWithParameters("Export diagnostics report", "System", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to json.", []string{"json", "csv"}, false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Diagnostics report export in JSON or CSV.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/diagnostics-exports", "get", securedOperation("List scheduled diagnostics exports", "System", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled diagnostics export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/diagnostics-exports/download", "get", securedOperationWithParameters("Download scheduled diagnostics export", "System", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "Diagnostics export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled diagnostics export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/network-apply", "post", securedOperationWithBody("Apply managed network state", "Network", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("Optional apply request metadata and confirmation details."), map[string]any{
		"200":     responseJSON("Apply result, validation details, and rollback snapshot references."),
		"default": responseText("Apply or validation error."),
	}))
	addOperation(paths, "/api/v1/system/network-recovery/confirm", "post", securedOperation("Confirm post-apply management reachability", "Network", []string{"ops_admin", "super_admin"}, map[string]any{
		"200":     responseJSON("Network recovery confirmation result."),
		"default": responseText("Recovery confirmation error."),
	}))
	addOperation(paths, "/api/v1/system/network-rollback", "post", securedOperationWithBody("Restore managed network snapshot", "Network", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("Snapshot identifier and optional restore metadata."), map[string]any{
		"200":     responseJSON("Rollback result."),
		"default": responseText("Rollback error."),
	}))

	addOperation(paths, "/api/v1/system/ha/history", "get", securedOperation("List HA history", "HA", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("High-availability event history and counters."),
	}))
	addOperation(paths, "/api/v1/system/ha/history/export", "get", securedOperation("Export HA history", "HA", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseBinary("text/csv", "HA history export."),
	}))
	addOperation(paths, "/api/v1/system/ha/exports", "get", securedOperation("List scheduled HA exports", "HA", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Scheduled HA export runtime status and recent artifact list."),
	}))
	addOperation(paths, "/api/v1/system/ha/exports/download", "get", securedOperationWithParameters("Download scheduled HA export", "HA", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("name", "HA export artifact filename.", true),
	}, map[string]any{
		"200": map[string]any{
			"description": "Scheduled HA export artifact in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/ha/replication-package", "get", securedOperation("Download HA replication package", "HA", []string{"ops_admin", "super_admin"}, map[string]any{
		"200": responseBinary("application/octet-stream", "HA replication package for a standby node."),
	}))
	addOperation(paths, "/api/v1/system/ha/replication-package", "post", securedOperationWithBody("Stage HA replication package on this node", "HA", []string{"ops_admin", "super_admin"}, multipartRequestBody(
		map[string]any{
			"package": map[string]any{"type": "string", "format": "binary", "description": "HA replication package."},
		},
		[]string{"package"},
		"Replication package to stage on this node.",
	), map[string]any{
		"200":     responseJSON("Staged HA package result."),
		"default": responseText("Staging error."),
	}))
	addOperation(paths, "/api/v1/system/ha/replication-shared", "get", securedOperation("Read shared HA replication state", "HA", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Current shared HA package publication metadata."),
	}))
	addOperation(paths, "/api/v1/system/ha/replication-staged", "get", securedOperation("List staged HA packages", "HA", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Staged HA replication packages on this node."),
	}))
	addOperation(paths, "/api/v1/system/ha/replication-stage-shared", "post", securedOperation("Stage latest shared HA package", "HA", []string{"ops_admin", "super_admin"}, map[string]any{
		"200":     responseJSON("Shared HA package staging result."),
		"default": responseText("Stage-shared error."),
	}))
	addOperation(paths, "/api/v1/system/ha/replication-activate", "post", securedOperationWithBody("Activate staged HA package", "HA", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("Staged package activation request."), map[string]any{
		"200":     responseJSON("HA activation result and restart handoff details."),
		"default": responseText("Activation error."),
	}))

	addOperation(paths, "/api/v1/system/hostapd-preview", "get", securedOperation("Preview hostapd configuration", "Wireless", []string{"super_admin"}, map[string]any{
		"200": responseJSON("Generated hostapd preview."),
	}))
	addOperation(paths, "/api/v1/system/hostapd-config", "post", securedOperation("Write hostapd configuration", "Wireless", []string{"super_admin"}, map[string]any{
		"200":     responseJSON("hostapd config write result."),
		"default": responseText("hostapd config error."),
	}))
	addOperation(paths, "/api/v1/system/hostapd-publish", "post", securedOperation("Publish hostapd configuration", "Wireless", []string{"super_admin"}, map[string]any{
		"200":     responseJSON("hostapd publish result."),
		"default": responseText("hostapd publish error."),
	}))
	addOperation(paths, "/api/v1/system/radius-apply", "post", securedOperation("Apply RADIUS runtime configuration", "RADIUS", []string{"super_admin"}, map[string]any{
		"200":     responseJSON("RADIUS apply result."),
		"default": responseText("RADIUS apply error."),
	}))
	addOperation(paths, "/api/v1/system/controller-adapters", "get", securedOperation("Read controller adapter catalog", "Integrations", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Controller adapter capabilities, selected adapter readiness, and runtime sync status."),
	}))
	addOperation(paths, "/api/v1/system/controller-sync/preview", "get", securedOperationWithParameters("Preview controller policy synchronization", "Integrations", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("operation", "Controller operation: pull or push.", false),
	}, map[string]any{
		"200":     responseJSON("Sanitized controller operation preview."),
		"default": responseText("Preview error."),
	}))
	addOperation(paths, "/api/v1/system/controller-sync", "post", securedOperationWithBody("Run controller policy synchronization", "Integrations", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("Controller operation and push confirmation."), map[string]any{
		"200":     responseJSON("Controller synchronization result."),
		"default": responseText("Controller synchronization error."),
	}))
	addOperation(paths, "/api/v1/system/vendor-compatibility", "get", securedOperation("Read vendor compatibility catalog", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("AegisNAS vendor dictionary catalog, semantic registry, dictionary coverage matrix, compatibility summary, and deployed NAS profile coverage."),
	}))
	addOperation(paths, "/api/v1/system/dictionary-release-profiles", "get", securedOperationWithParameters("Read dictionary release profiles", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("id", "Optional exact release profile ID such as freeradius-3.2.8.", false),
	}, map[string]any{
		"200": responseJSON("Pinned dictionary release profiles, alias normalization tables, firmware scopes, and active/default profile IDs."),
		"404": responseJSON("Requested dictionary release profile was not found."),
	}))
	addOperation(paths, "/api/v1/system/compatibility-evidence", "get", securedOperationWithParameters("Read compatibility evidence states", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("pack", "Normalized compatibility pack filter.", false),
		queryStringParameter("vendor", "Case-insensitive vendor filter.", false),
		queryStringParameter("semantic", "Exact vendor-neutral semantic filter.", false),
		queryEnumParameter("software_state", "Software readiness state.", []string{"ready", "planned", "blocked", "metadata_only"}, false),
		queryEnumParameter("certification_state", "External certification state.", []string{"not_required", "external_required", "certified"}, false),
		queryEnumParameter("claim", "Compatibility claim state.", []string{"software_ready", "software_ready_external_required", "planned", "blocked", "metadata_only"}, false),
		queryStringParameter("search", "Case-insensitive pack, vendor, attribute, semantic, direction, or state search.", false),
		queryStringParameter("limit", "Page size from 1 to 500; defaults to 100.", false),
		queryStringParameter("cursor", "Opaque cursor returned by the previous page.", false),
	}, map[string]any{
		"200": responseJSON("Compatibility evidence summary, filtered records, dimensions, and next cursor."),
		"400": responseJSON("Invalid filter, limit, or cursor."),
	}))
	addOperation(paths, "/api/v1/system/vsa-codec", "get", securedOperation("Read VSA codec capabilities", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Extended, grouped, tagged, and repeated VSA codec readiness."),
	}))
	addOperation(paths, "/api/v1/system/opaque-passthrough", "get", securedOperation("Read opaque attribute pass-through policy", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Effective bounded pass-through policy, default-drop state, rule counts, sensitive denylist, and registry provenance."),
	}))
	addOperation(paths, "/api/v1/system/radius-hardening", "get", securedOperation("Read RADIUS packet hardening policy", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("RADIUS packet hardening policy, supported packet codes, source trust, limits, runtime counters, and recent decisions."),
	}))
	addOperation(paths, "/api/v1/system/radsec-credentials", "get", securedOperation("Read RadSec credential and rotation state", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("RadSec mTLS and TLS-PSK credential state, rotation windows, redacted secret references, warnings, and blockers."),
	}))
	addOperation(paths, "/api/v1/system/nas-clients", "get", securedOperation("Read dynamic NAS client lifecycle", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Dynamic NAS enrollment policy, approval queue, capability templates, inventory summary, and recent lifecycle events."),
	}))
	addOperation(paths, "/api/v1/system/nas-clients/enrollments", "get", securedOperationWithParameters("List dynamic NAS enrollments", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("status", "Optional enrollment status filter.", []string{"pending", "approved", "rejected", "revoked", "expired"}, false),
		queryStringParameter("limit", "Record limit from 1 to 1000.", false),
	}, map[string]any{
		"200": responseJSON("Dynamic NAS enrollment records."),
	}))
	addOperation(paths, "/api/v1/system/nas-clients/enrollments", "post", securedOperationWithBody("Create dynamic NAS enrollment", "RADIUS", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("Enrollment metadata to seed or refresh."), map[string]any{
		"201":     responseJSON("Created pending NAS enrollment."),
		"default": responseText("Enrollment validation error."),
	}))
	for _, action := range []string{"approve", "reject", "revoke"} {
		addOperation(paths, "/api/v1/system/nas-clients/enrollments/{id}/"+action, "post", securedOperationWithParameters("Update dynamic NAS enrollment "+action, "RADIUS", []string{"ops_admin", "super_admin"}, []map[string]any{idParameter("id", "Enrollment identifier.")}, map[string]any{
			"200":     responseJSON("Updated dynamic NAS enrollment."),
			"default": responseText("Lifecycle transition error."),
		}))
	}
	addOperation(paths, "/api/v1/system/nas-clients/templates", "get", securedOperation("List NAS capability templates", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Capability templates used to gate dynamic NAS approvals."),
	}))
	addOperation(paths, "/api/v1/system/nas-clients/templates", "post", securedOperationWithBody("Create NAS capability template", "RADIUS", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("Capability template payload."), map[string]any{
		"200":     responseJSON("Saved capability template."),
		"default": responseText("Template validation error."),
	}))
	addOperation(paths, "/api/v1/system/nas-clients/templates/{name}", "put", securedOperationWithParameters("Update NAS capability template", "RADIUS", []string{"ops_admin", "super_admin"}, []map[string]any{idParameter("name", "Capability template name.")}, map[string]any{
		"200":     responseJSON("Saved capability template."),
		"default": responseText("Template validation error."),
	}))
	addOperation(paths, "/api/v1/system/nas-clients/templates/{name}", "delete", securedOperationWithParameters("Delete NAS capability template", "RADIUS", []string{"ops_admin", "super_admin"}, []map[string]any{idParameter("name", "Capability template name.")}, map[string]any{
		"200":     responseJSON("Delete result."),
		"default": responseText("Template validation error."),
	}))
	addOperation(paths, "/api/v1/system/proxy-routes", "get", securedOperation("Read RADIUS proxy routing table", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Effective multi-realm proxy routes, route pools, default fallback behavior, upstream servers, and validation warnings."),
	}))
	addOperation(paths, "/api/v1/system/transport-policy", "get", securedOperation("Read RADIUS transport downgrade policy", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Effective proxy transport downgrade policy, route transport requirements, mixed-transport risks, and enforcement state."),
	}))
	addOperation(paths, "/api/v1/system/proxy-policy", "get", securedOperation("Read RADIUS proxy loop and attribute policy", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Effective proxy loop marker, route trust, attribute allow/deny, rewrite policy, FreeRADIUS enforcement state, and readiness warnings."),
	}))
	addOperation(paths, "/api/v1/system/accounting-spool", "get", securedOperationWithParameters("Read durable RADIUS accounting spool state", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("status", "Optional spool record status filter.", []string{"queued", "retrying", "sent", "poison", "expired"}, false),
		queryStringParameter("record_id", "Optional spool record ID for attempt history.", false),
		queryStringParameter("limit", "Record or attempt limit from 1 to 1000.", false),
	}, map[string]any{
		"200": responseJSON("Accounting spool policy, summary, recent records, optional filtered records, and attempt history."),
	}))
	addOperation(paths, "/api/v1/system/accounting-spool/replay", "post", securedOperation("Replay due durable RADIUS accounting records", "RADIUS", []string{"ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Replay run result with claimed, sent, failed, poisoned, expired, and queue summary counts."),
	}))
	addOperation(paths, "/api/v1/system/fallback-policy", "get", securedOperationWithParameters("Read upstream outage fallback policy", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("decision", "Optional audited decision filter.", []string{"allowed", "denied"}, false),
		queryStringParameter("source", "Optional fallback source filter such as portal.", false),
		queryStringParameter("limit", "Event limit from 1 to 5000.", false),
	}, map[string]any{
		"200": responseJSON("Effective outage fallback policy, allowlist posture, audit summary, and recent local/LDAP fallback decisions."),
	}))
	addOperation(paths, "/api/v1/system/identity-failover", "get", securedOperationWithParameters("Read identity source failover state", "Authentication", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("source", "Optional identity source name filter such as local or ldap-primary.", false),
		queryEnumParameter("decision", "Optional audited decision filter.", []string{"accepted", "rejected", "not_found", "failed", "skipped", "stale_accepted", "split_denied"}, false),
		queryStringParameter("limit", "Event limit from 1 to 5000.", false),
	}, map[string]any{
		"200": responseJSON("Effective identity-source failover policy, deterministic source plan, circuit state, cache summary, audit summary, and recent source decisions."),
	}))
	addOperation(paths, "/api/v1/system/active-directory", "get", securedOperationWithParameters("Read Active Directory identity state", "Authentication", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("source", "Optional Active Directory source name filter.", false),
		queryEnumParameter("decision", "Optional audited decision filter.", []string{"accepted", "rejected", "not_found", "failed", "skipped"}, false),
		queryStringParameter("component", "Optional health component filter such as ldap_dns or winbind_trust.", false),
		queryStringParameter("limit", "Event or health limit from 1 to 5000.", false),
	}, map[string]any{
		"200": responseJSON("Effective Active Directory policy, Kerberos/winbind posture, group cache summary, health summary, and recent decisions."),
	}))
	addOperation(paths, "/api/v1/system/active-directory/check", "post", securedOperation("Run Active Directory health checks", "Authentication", []string{"ops_admin", "super_admin"}, map[string]any{
		"200":     responseJSON("Fresh Active Directory health check results and updated report."),
		"default": responseText("Health check error."),
	}))
	addOperation(paths, "/api/v1/system/mfa", "get", securedOperationWithParameters("Read OTP and RADIUS challenge MFA state", "Authentication", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("decision", "Optional audited decision filter.", []string{"challenge_issued", "accepted", "denied", "monitor_allowed", "enrolled"}, false),
		queryEnumParameter("method", "Optional MFA method filter.", []string{"totp", "recovery"}, false),
		queryStringParameter("limit", "Event limit from 1 to 5000.", false),
	}, map[string]any{
		"200": responseJSON("Effective MFA policy, encrypted enrollment posture, challenge state, recovery-code summary, audit summary, and recent decisions."),
	}))
	addOperation(paths, "/api/v1/system/mfa/enroll", "post", securedOperationWithBody("Enroll a user for TOTP MFA", "Authentication", []string{"super_admin"}, genericJSONObjectRequest("Username to enroll. The response returns the TOTP secret and recovery codes once."), map[string]any{
		"201":     responseJSON("TOTP enrollment with username hash, otpauth URL, secret, and one-time recovery codes."),
		"default": responseJSON("MFA enrollment error."),
	}))
	addOperation(paths, "/api/v1/system/mfa/verify", "post", securedOperationWithBody("Verify an MFA code for controlled testing", "Authentication", []string{"super_admin"}, genericJSONObjectRequest("Username and TOTP or recovery code."), map[string]any{
		"200":     responseJSON("Verification result with method and reason."),
		"default": responseJSON("MFA verification error."),
	}))
	addOperation(paths, "/api/v1/system/mfa/recovery-codes", "post", securedOperationWithBody("Rotate MFA recovery codes", "Authentication", []string{"super_admin"}, genericJSONObjectRequest("Username whose recovery codes should be replaced."), map[string]any{
		"201":     responseJSON("Replacement recovery codes returned once with username hash."),
		"default": responseJSON("MFA recovery-code rotation error."),
	}))
	addOperation(paths, "/api/v1/system/webauthn", "get", securedOperationWithParameters("Read admin WebAuthn passkey state", "Authentication", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("decision", "Optional audited decision filter.", []string{"challenge_issued", "registered", "accepted", "denied", "monitor_allowed"}, false),
		queryEnumParameter("ceremony", "Optional ceremony filter.", []string{"registration", "authentication"}, false),
		queryStringParameter("subject", "Optional admin subject filter for credentials.", false),
		queryStringParameter("limit", "Credential or event limit from 1 to 5000.", false),
	}, map[string]any{
		"200": responseJSON("Effective WebAuthn policy, credential inventory, challenge posture, audit summary, and recent events."),
	}))
	addOperation(paths, "/api/v1/system/webauthn/register/options", "post", securedOperationWithBody("Start admin passkey registration", "Authentication", []string{"super_admin"}, genericJSONObjectRequest("Admin subject, display name, and credential label."), map[string]any{
		"201":     responseJSON("WebAuthn PublicKeyCredentialCreationOptions and pending state."),
		"default": responseJSON("Passkey registration challenge error."),
	}))
	addOperation(paths, "/api/v1/system/webauthn/register/finish", "post", securedOperationWithBody("Finish admin passkey registration", "Authentication", []string{"super_admin"}, genericJSONObjectRequest("Pending state and browser attestation credential."), map[string]any{
		"201":     responseJSON("Stored passkey credential metadata."),
		"default": responseJSON("Passkey registration verification error."),
	}))
	addOperation(paths, "/api/v1/system/webauthn/credentials/{id}", "delete", securedOperation("Revoke an admin passkey credential", "Authentication", []string{"super_admin"}, map[string]any{
		"204":     responseText("Credential revoked."),
		"default": responseJSON("Credential revoke error."),
	}))
	addOperation(paths, "/api/v1/system/eap-framework", "get", securedOperationWithParameters("Read extensible EAP method framework state", "Authentication", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("method", "Optional EAP method filter for recent events.", false),
		queryEnumParameter("decision", "Optional audited decision filter.", []string{"accepted", "rejected", "monitor_allowed", "unsupported"}, false),
		queryStringParameter("nas_type", "Optional NAS type filter for recent events.", false),
		queryStringParameter("limit", "Event limit from 1 to 5000.", false),
	}, map[string]any{
		"200": responseJSON("Typed EAP catalog, effective method policy, identity-source bindings, vendor compatibility profiles, runtime summary, and recent EAP method events."),
	}))
	addOperation(paths, "/api/v1/system/eap-framework/evaluate", "post", securedOperationWithBody("Evaluate an EAP method decision", "Authentication", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("RADIUS-like EAP request fields: method, inner_method, NAS type, identity source, EAP-Message presence, Message-Authenticator presence, certificate state, and optional audit flag."), map[string]any{
		"200":     responseJSON("Deterministic EAP framework decision and audit status."),
		"default": responseJSON("EAP framework evaluation error."),
	}))
	addOperation(paths, "/api/v1/system/eap-framework/teap", "get", securedOperationWithParameters("Read TEAP method-chaining state", "Authentication", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("decision", "Optional audited TEAP decision filter.", []string{"accepted", "rejected", "monitor_allowed"}, false),
		queryEnumParameter("chain_mode", "Optional TEAP chain mode filter.", []string{"user_only", "machine_only", "machine_then_user", "either"}, false),
		queryStringParameter("nas_type", "Optional NAS type filter for recent TEAP events.", false),
		queryStringParameter("limit", "Event limit from 1 to 5000.", false),
	}, map[string]any{
		"200": responseJSON("TEAP policy, RFC 7170 TLV coverage, runtime summary, release evidence checklist, and recent chain events."),
	}))
	addOperation(paths, "/api/v1/system/eap-framework/teap/evaluate", "post", securedOperationWithBody("Evaluate a TEAP method-chain decision", "Authentication", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("TEAP chain facts: inner method, NAS type, machine/user identities, Message-Authenticator, TLS version, cryptobinding, channel-binding, PAC, Identity-Type, Result TLVs, and optional audit flag."), map[string]any{
		"200":     responseJSON("Deterministic TEAP chain decision and audit status."),
		"default": responseJSON("TEAP evaluation error."),
	}))
	addOperation(paths, "/api/v1/system/eap-framework/fast-pwd", "get", securedOperationWithParameters("Read EAP-FAST and EAP-PWD state", "Authentication", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("method", "Optional audited method filter.", []string{"fast", "pwd"}, false),
		queryEnumParameter("decision", "Optional audited decision filter.", []string{"accepted", "rejected", "monitor_allowed"}, false),
		queryStringParameter("nas_type", "Optional NAS type filter for recent FAST/PWD events.", false),
		queryStringParameter("limit", "Event limit from 1 to 5000.", false),
	}, map[string]any{
		"200": responseJSON("EAP-FAST PAC policy, EAP-PWD group policy, attribute capability catalog, runtime summary, release evidence checklist, and recent method events."),
	}))
	addOperation(paths, "/api/v1/system/eap-framework/fast-pwd/evaluate", "post", securedOperationWithBody("Evaluate an EAP-FAST or EAP-PWD decision", "Authentication", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("FAST/PWD method facts: method, inner method, NAS type, identity, Message-Authenticator, TLS version, cryptobinding, PAC state, PWD group, password proof, replay state, and optional audit flag."), map[string]any{
		"200":     responseJSON("Deterministic EAP-FAST/PWD decision and audit status."),
		"default": responseJSON("EAP-FAST/PWD evaluation error."),
	}))
	addOperation(paths, "/api/v1/system/eap-framework/sim-aka", "get", securedOperationWithParameters("Read EAP-SIM, EAP-AKA, and EAP-AKA-prime state", "Authentication", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("method", "Optional audited method filter.", []string{"sim", "aka", "aka-prime"}, false),
		queryEnumParameter("decision", "Optional audited decision filter.", []string{"accepted", "rejected", "monitor_allowed"}, false),
		queryStringParameter("nas_type", "Optional NAS type filter for recent SIM/AKA events.", false),
		queryStringParameter("limit", "Event limit from 1 to 5000.", false),
	}, map[string]any{
		"200": responseJSON("EAP-SIM/AKA vector-provider policy, identity privacy controls, attribute capability catalog, runtime summary, release evidence checklist, and recent method events."),
	}))
	addOperation(paths, "/api/v1/system/eap-framework/sim-aka/evaluate", "post", securedOperationWithBody("Evaluate an EAP-SIM, EAP-AKA, or EAP-AKA-prime decision", "Authentication", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("SIM/AKA method facts: method, NAS type, mobile identities, Message-Authenticator, vector provider, vector freshness, triplet/quintuplet evidence, resync, network-name/KDF, replay state, and optional audit flag."), map[string]any{
		"200":     responseJSON("Deterministic EAP-SIM/AKA decision and audit status."),
		"default": responseJSON("EAP-SIM/AKA evaluation error."),
	}))
	addOperation(paths, "/api/v1/system/mab", "get", securedOperationWithParameters("Read MAC Authentication Bypass state", "Authentication", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("decision", "Optional audited decision filter.", []string{"accepted", "rejected", "quarantined", "monitor_allowed", "fail_open", "unsupported"}, false),
		queryStringParameter("mac", "Optional endpoint MAC filter in colon, hyphen, plain, or Cisco dotted format.", false),
		queryStringParameter("limit", "Event limit from 1 to 5000.", false),
	}, map[string]any{
		"200": responseJSON("Effective MAB policy, endpoint summary, audit summary, recent decisions, and readiness state."),
	}))
	addOperation(paths, "/api/v1/system/mab/endpoints", "get", securedOperationWithParameters("List MAB endpoint inventory", "Authentication", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("status", "Optional endpoint status filter.", []string{"approved", "pending", "quarantined", "denied", "expired"}, false),
		queryStringParameter("limit", "Endpoint limit from 1 to 50000.", false),
	}, map[string]any{
		"200": responseJSON("Persistent MAB endpoint records with role, VLAN, ACL, tenant, posture, and profile snapshot fields."),
	}))
	addOperation(paths, "/api/v1/system/mab/endpoints", "post", securedOperationWithBody("Create or update a MAB endpoint", "Authentication", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("Endpoint MAC, status, optional role, VLAN, ACL, tenant, posture, expiration, and profile snapshot."), map[string]any{
		"201":     responseJSON("Stored MAB endpoint."),
		"default": responseJSON("MAB endpoint validation error."),
	}))
	addOperation(paths, "/api/v1/system/mab/endpoints/{mac}", "put", securedOperationWithBody("Update a MAB endpoint by MAC", "Authentication", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("Endpoint status and optional policy overrides."), map[string]any{
		"201":     responseJSON("Stored MAB endpoint."),
		"default": responseJSON("MAB endpoint validation error."),
	}))
	addOperation(paths, "/api/v1/system/mab/endpoints/{mac}", "delete", securedOperation("Delete a MAB endpoint by MAC", "Authentication", []string{"ops_admin", "super_admin"}, map[string]any{
		"200":     responseJSON("Endpoint deletion result."),
		"default": responseJSON("MAB endpoint deletion error."),
	}))
	addOperation(paths, "/api/v1/system/mab/evaluate", "post", securedOperationWithBody("Evaluate a MAB access request", "Authentication", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("RADIUS-like request fields: username, Calling-Station-Id, NAS identity, NAS-Port-Type, EAP presence, and optional audit recording."), map[string]any{
		"200":     responseJSON("Deterministic MAB decision with endpoint/profile context and enforcement state."),
		"default": responseJSON("MAB evaluation error."),
	}))
	addOperation(paths, "/api/v1/system/secret-providers", "get", securedOperation("Read secret provider readiness", "Security", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Redacted secret-provider inventory, reference status, inline-secret blockers, and provider policy."),
	}))
	addOperation(paths, "/api/v1/system/database", "get", securedOperation("Read database data-plane readiness", "System", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Redacted database backend, schema, pool, TLS, and HA readiness status."),
	}))
	addOperation(paths, "/api/v1/system/attribute-registry", "get", securedOperationWithParameters("Read the generated typed attribute registry", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("release", "Optional dictionary release profile ID; defaults to the active embedded profile.", false),
		queryStringParameter("vendor", "Exact vendor namespace filter.", false),
		queryStringParameter("pen", "Exact Private Enterprise Number filter.", false),
		queryStringParameter("pack", "Normalized compatibility pack filter.", false),
		queryStringParameter("semantic", "Exact vendor-neutral semantic filter.", false),
		queryEnumParameter("status", "Dictionary status.", []string{"missing", "partial", "implemented"}, false),
		queryStringParameter("search", "Case-insensitive attribute, vendor, semantic, capability, and functionality search.", false),
		queryStringParameter("limit", "Page size from 1 to 500; defaults to 100.", false),
		queryStringParameter("cursor", "Opaque cursor returned by the previous page.", false),
	}, map[string]any{
		"200": responseJSON("Pinned registry provenance, counts, filtered typed attributes, and the next cursor."),
		"400": responseJSON("Invalid filter, limit, or cursor."),
	}))
	addOperation(paths, "/api/v1/system/vendor-identity", "get", securedOperationWithParameters("Read AegisNAS vendor identity lifecycle", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("limit", "Migration history rows to return, from 1 to 500.", false),
	}, map[string]any{
		"200": responseJSON("Current PEN lifecycle, verified assignment evidence, legacy decode window, migration history, and counters."),
	}))
	addOperation(paths, "/api/v1/system/vendor-identity/migrations/preview", "post", securedOperationWithBody("Preview and verify a production PEN migration", "RADIUS", []string{"super_admin"}, genericJSONObjectRequest("Assigned PEN, exact IANA organization, and optional legacy acceptance hours."), map[string]any{
		"200":     responseJSON("Verified migration preview and one-time confirmation token."),
		"default": responseJSON("Stable vendor identity error response."),
	}))
	addOperation(paths, "/api/v1/system/vendor-identity/migrations/apply", "post", securedOperationWithBody("Apply a verified production PEN migration", "RADIUS", []string{"super_admin"}, genericJSONObjectRequest("Migration ID and one-time confirmation token."), map[string]any{
		"200":     responseJSON("Applied identity and FreeRADIUS restart result."),
		"default": responseJSON("Stable vendor identity error response."),
	}))
	addOperation(paths, "/api/v1/system/vendor-identity/migrations/{id}/rollback", "post", securedOperationWithParametersAndBody("Roll back a vendor identity migration", "RADIUS", []string{"super_admin"}, []map[string]any{
		idParameter("id", "Vendor identity migration ID."),
	}, genericJSONObjectRequest("Exact rollback confirmation text."), map[string]any{
		"200":     responseJSON("Restored identity and FreeRADIUS restart result."),
		"default": responseJSON("Stable vendor identity error response."),
	}))
	addOperation(paths, "/api/v1/system/production-readiness", "get", securedOperation("Read production readiness report", "Operations", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Production deployment readiness checks covering config validation, hardware scaling, vendor identity, NAS profile coverage, feature gates, controller readiness, and vendor runtime evidence."),
	}))
	addOperation(paths, "/api/v1/system/vendor-observability", "get", securedOperationWithParameters("Read vendor observability counters", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryStringParameter("limit", "Optional vendor row limit. Defaults to 100 and caps at 5000.", false),
	}, map[string]any{
		"200": responseJSON("Per-vendor auth, VSA parse, unsupported attribute, CoA, disconnect, and compatibility score counters."),
	}))
	addOperation(paths, "/api/v1/system/vendor-observability/export", "get", securedOperationWithParameters("Export vendor observability counters", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{
		queryEnumParameter("format", "Optional export format. Defaults to csv.", []string{"json", "csv"}, false),
	}, map[string]any{
		"200": map[string]any{
			"description": "Vendor observability export in JSON or CSV form.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
				},
				"text/csv": map[string]any{
					"schema": map[string]any{
						"type": "string",
					},
				},
			},
		},
	}))
	addOperation(paths, "/api/v1/system/vendor-reply-preview", "post", securedOperationWithBody("Preview vendor reply attributes", "RADIUS", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, genericJSONObjectRequest("NAS type, role, VLAN, bandwidth, timeout, ACL names, and ACL rule intent to preview."), map[string]any{
		"200":     responseJSON("Effective compatibility packs and rendered RADIUS reply attributes."),
		"default": responseText("Preview error."),
	}))

	addCRUDOperations(paths, "/api/v1/vlans", "VLANs", "VLAN", []string{"super_admin"}, []string{"super_admin"})
	addCRUDOperations(paths, "/api/v1/users", "Users", "User", []string{"super_admin"}, []string{"super_admin"})
	addCollectionOnly(paths, "/api/v1/devices", "Devices", "Device inventory", []string{"read_only", "guest_admin", "ops_admin", "super_admin"})
	addOperation(paths, "/api/v1/devices/profile-observations", "post", securedOperationWithBody("Record device profile observation", "Devices", []string{"ops_admin", "super_admin"}, genericJSONObjectRequest("Device profile signals such as MAC, IP, user-agent, DHCP fingerprint, LLDP, and CDP fields."), map[string]any{
		"200":     responseJSON("Stored profile observation, risk score, risk reasons, and auto-quarantine count."),
		"default": responseText("Profile observation error."),
	}))
	addOperation(paths, "/api/v1/devices/certificates", "get", securedOperation("List device certificates", "Devices", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200": responseJSON("Device certificate inventory with active, expired, and revoked lifecycle status."),
	}))
	addOperation(paths, "/api/v1/devices/certificates/crl", "get", securedOperation("Download device certificate revocation list", "Devices", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, map[string]any{
		"200":     responseBinary("application/pkix-crl", "Internal CA certificate revocation list."),
		"default": responseText("CRL generation error."),
	}))
	addOperation(paths, "/api/v1/devices/certificates/{id}/status", "get", securedOperationWithParameters("Read device certificate lifecycle status", "Devices", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{idParameter("id", "Certificate identifier.")}, map[string]any{
		"200":     responseJSON("Certificate lifecycle status."),
		"default": responseText("Certificate lookup error."),
	}))
	addOperation(paths, "/api/v1/devices/certificates/{id}/revoke", "post", securedOperationWithParametersAndBody("Revoke device certificate", "Devices", []string{"ops_admin", "super_admin"}, []map[string]any{idParameter("id", "Certificate identifier.")}, genericJSONObjectRequest("Revocation reason."), map[string]any{
		"200":     responseJSON("Updated certificate lifecycle status."),
		"default": responseText("Certificate revocation error."),
	}))
	addOperation(paths, "/api/v1/devices/certificates/{id}/renew", "post", securedOperationWithParameters("Renew device certificate", "Devices", []string{"ops_admin", "super_admin"}, []map[string]any{idParameter("id", "Certificate identifier.")}, map[string]any{
		"200":     responseJSON("Renewed device registration and replacement certificate bundle metadata."),
		"default": responseText("Certificate renewal error."),
	}))
	addOperation(paths, "/api/v1/devices/{id}/certificate", "get", securedOperationWithParameters("Download device certificate bundle", "Devices", []string{"read_only", "guest_admin", "ops_admin", "super_admin"}, []map[string]any{idParameter("id", "Device identifier.")}, map[string]any{
		"200":     responseBinary("application/octet-stream", "Device certificate bundle."),
		"default": responseText("Certificate export error."),
	}))
	addCollectionOnly(paths, "/api/v1/admin-principals", "Admin Access", "Admin principals", []string{"super_admin"})
	addOperation(paths, "/api/v1/admin-principals/{id}", "put", securedOperationWithParametersAndBody("Update admin principal", "Admin Access", []string{"super_admin"}, []map[string]any{idParameter("id", "Admin principal identifier.")}, genericJSONObjectRequest("Admin principal updates."), map[string]any{
		"200":     responseJSON("Updated admin principal."),
		"default": responseText("Update error."),
	}))
	addCollectionOnly(paths, "/api/v1/guest-registrations", "Guest", "Guest registrations", []string{"read_only", "guest_admin", "ops_admin", "super_admin"})
	addOperation(paths, "/api/v1/guest-registrations/{id}/approve", "post", securedOperationWithParameters("Approve guest registration", "Guest", []string{"guest_admin", "ops_admin", "super_admin"}, []map[string]any{idParameter("id", "Guest registration identifier.")}, map[string]any{
		"200":     responseJSON("Guest registration approval result."),
		"default": responseText("Approval error."),
	}))
	addOperation(paths, "/api/v1/guest-registrations/{id}/reject", "post", securedOperationWithParameters("Reject guest registration", "Guest", []string{"guest_admin", "ops_admin", "super_admin"}, []map[string]any{idParameter("id", "Guest registration identifier.")}, map[string]any{
		"200":     responseJSON("Guest registration rejection result."),
		"default": responseText("Rejection error."),
	}))
	addCRUDOperations(paths, "/api/v1/vouchers", "Vouchers", "Voucher", []string{"super_admin"}, []string{"super_admin"})
	addCRUDOperations(paths, "/api/v1/roles", "Roles", "Role", []string{"super_admin"}, []string{"super_admin"})
	addCRUDOperations(paths, "/api/v1/policies", "Policies", "Policy", []string{"super_admin"}, []string{"super_admin"})
	addCRUDOperations(paths, "/api/v1/acl-policies", "ACL Policies", "ACL policy", []string{"super_admin"}, []string{"super_admin"})
	addCRUDOperations(paths, "/api/v1/identity-sources", "Identity Sources", "Identity source", []string{"super_admin"}, []string{"super_admin"})
	addCRUDOperations(paths, "/api/v1/portal-profiles", "Portal Profiles", "Portal profile", []string{"super_admin"}, []string{"super_admin"})
	addCRUDOperations(paths, "/api/v1/bandwidth-profiles", "Bandwidth Profiles", "Bandwidth profile", []string{"super_admin"}, []string{"super_admin"})
	addCRUDOperations(paths, "/api/v1/radius-clients", "RADIUS Clients", "RADIUS client", []string{"super_admin"}, []string{"super_admin"})
	addCollectionOnly(paths, "/api/v1/sessions", "Sessions", "Active sessions", []string{"read_only", "guest_admin", "ops_admin", "super_admin"})
	addOperation(paths, "/api/v1/sessions/{id}", "delete", securedOperationWithParameters("Terminate session", "Sessions", []string{"guest_admin", "ops_admin", "super_admin"}, []map[string]any{idParameter("id", "Session identifier.")}, map[string]any{
		"200":     responseJSON("Session termination result."),
		"default": responseText("Termination error."),
	}))
	addCollectionOnly(paths, "/api/v1/alerts", "Alerts", "Alert stream", []string{"read_only", "guest_admin", "ops_admin", "super_admin"})
	addOperation(paths, "/api/v1/alerts/{id}/acknowledge", "post", securedOperationWithParameters("Acknowledge alert", "Alerts", []string{"ops_admin", "super_admin"}, []map[string]any{idParameter("id", "Alert identifier.")}, map[string]any{
		"200":     responseJSON("Alert acknowledgement result."),
		"default": responseText("Acknowledge error."),
	}))
	addCollectionOnly(paths, "/api/v1/config-revisions", "Config Revisions", "Config revision list", []string{"ops_admin", "super_admin"})
	addOperation(paths, "/api/v1/config/rollback/{revision}", "post", securedOperationWithParameters("Roll back to config revision", "Config Revisions", []string{"super_admin"}, []map[string]any{idParameter("revision", "Config revision identifier.")}, map[string]any{
		"200":     responseJSON("Config rollback result."),
		"default": responseText("Rollback error."),
	}))
	addOperation(paths, "/api/v1/backups/config", "get", securedOperation("Download config JSON backup", "Backups", []string{"super_admin"}, map[string]any{
		"200": responseBinary("application/json", "Config JSON backup."),
	}))
	addOperation(paths, "/api/v1/backups/config", "post", securedOperationWithBody("Restore config JSON backup", "Backups", []string{"super_admin"}, requestBody("application/json", map[string]any{"type": "object", "additionalProperties": true}, true, "Config JSON backup payload."), map[string]any{
		"200":     responseJSON("Config import result."),
		"default": responseText("Config import error."),
	}))
	addCollectionOnly(paths, "/api/v1/ai-recommendations", "AI", "AI recommendations", []string{"read_only", "guest_admin", "ops_admin", "super_admin"})
	addOperation(paths, "/api/v1/ai-recommendations/run", "post", securedOperation("Run AI analysis", "AI", []string{"ops_admin", "super_admin"}, map[string]any{
		"200":     responseJSON("AI analysis trigger result."),
		"default": responseText("AI analysis error."),
	}))
	addOperation(paths, "/api/v1/ai-recommendations/{id}/acknowledge", "post", securedOperationWithParameters("Acknowledge AI recommendation", "AI", []string{"ops_admin", "super_admin"}, []map[string]any{idParameter("id", "AI recommendation identifier.")}, map[string]any{
		"200":     responseJSON("AI acknowledgement result."),
		"default": responseText("Acknowledgement error."),
	}))
	addCollectionOnly(paths, "/api/v1/staged-changes", "Workflow", "Staged changes", []string{"super_admin"})
	addOperation(paths, "/api/v1/apply", "post", securedOperation("Apply staged changes", "Workflow", []string{"super_admin"}, map[string]any{
		"200":     responseJSON("Apply staged changes result."),
		"default": responseText("Apply error."),
	}))
	addOperation(paths, "/api/v1/validate", "post", securedOperation("Validate staged changes", "Workflow", []string{"super_admin"}, map[string]any{
		"200":     responseJSON("Validation result for staged changes."),
		"default": responseText("Validation error."),
	}))

	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "AegisNAS Admin API",
			"version":     "1.0.0",
			"description": "Operational API for AegisNAS administration, upgrade safety, HA workflows, guest access, and runtime observability.",
		},
		"servers": buildOpenAPIServers(r, cfg),
		"tags": []map[string]any{
			{"name": "Documentation"}, {"name": "Health"}, {"name": "Authentication"},
			{"name": "System"}, {"name": "Upgrade"}, {"name": "Network"}, {"name": "Integrations"}, {"name": "HA"},
			{"name": "Wireless"}, {"name": "RADIUS"}, {"name": "VLANs"}, {"name": "Users"},
			{"name": "Devices"}, {"name": "Admin Access"}, {"name": "Guest"}, {"name": "Vouchers"},
			{"name": "Roles"}, {"name": "Policies"}, {"name": "ACL Policies"}, {"name": "Identity Sources"},
			{"name": "Portal Profiles"}, {"name": "Bandwidth Profiles"}, {"name": "RADIUS Clients"},
			{"name": "Sessions"}, {"name": "Alerts"}, {"name": "Config Revisions"},
			{"name": "Backups"}, {"name": "AI"}, {"name": "Workflow"},
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "token",
					"description":  "Admin API bearer token or SSO-issued admin session token.",
				},
			},
		},
		"paths": paths,
	}
}

func buildOpenAPIServers(r *http.Request, cfg *config.Config) []map[string]any {
	servers := []map[string]any{{
		"url":         "/",
		"description": "Relative server root for browser-based admin UI and proxied API calls.",
	}}
	if r == nil {
		return servers
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = forwarded
	}
	host := strings.TrimSpace(r.Host)
	if host == "" && cfg != nil && cfg.AdminPort > 0 {
		host = fmt.Sprintf("127.0.0.1:%d", cfg.AdminPort)
	}
	if host != "" {
		servers = append(servers, map[string]any{
			"url":         fmt.Sprintf("%s://%s", scheme, host),
			"description": "Current admin API host.",
		})
	}
	return servers
}

func addCRUDOperations(paths map[string]any, basePath, tag, resourceLabel string, readRoles, writeRoles []string) {
	addOperation(paths, basePath, "get", securedOperation("List "+pluralResourceLabel(resourceLabel), tag, readRoles, map[string]any{
		"200": responseJSON("Collection response."),
	}))
	addOperation(paths, basePath, "post", securedOperationWithBody("Create "+resourceLabel, tag, writeRoles, genericJSONObjectRequest(resourceLabel+" payload to create."), map[string]any{
		"200":     responseJSON("Created resource."),
		"default": responseText("Create error."),
	}))
	addOperation(paths, basePath+"/{id}", "put", securedOperationWithParametersAndBody("Update "+resourceLabel, tag, writeRoles, []map[string]any{idParameter("id", resourceLabel+" identifier.")}, genericJSONObjectRequest(resourceLabel+" payload to update."), map[string]any{
		"200":     responseJSON("Updated resource."),
		"default": responseText("Update error."),
	}))
	addOperation(paths, basePath+"/{id}", "delete", securedOperationWithParameters("Delete "+resourceLabel, tag, writeRoles, []map[string]any{idParameter("id", resourceLabel+" identifier.")}, map[string]any{
		"200":     responseJSON("Delete result."),
		"default": responseText("Delete error."),
	}))
}

func pluralResourceLabel(label string) string {
	if len(label) > 1 && strings.HasSuffix(strings.ToLower(label), "y") {
		previous := strings.ToLower(label[len(label)-2 : len(label)-1])
		if !strings.Contains("aeiou", previous) {
			return label[:len(label)-1] + "ies"
		}
	}
	return label + "s"
}

func addCollectionOnly(paths map[string]any, basePath, tag, summary string, roles []string) {
	addOperation(paths, basePath, "get", securedOperation("List "+summary, tag, roles, map[string]any{
		"200": responseJSON("Collection response."),
	}))
}

func addOperation(paths map[string]any, route, method string, operation map[string]any) {
	key := strings.TrimSpace(route)
	methodKey := strings.ToLower(strings.TrimSpace(method))
	if key == "" || methodKey == "" || operation == nil {
		return
	}
	pathItem, _ := paths[key].(map[string]any)
	if pathItem == nil {
		pathItem = map[string]any{}
	}
	pathItem[methodKey] = operation
	paths[key] = pathItem
}

func openAPIOperation(summary, tag string, parameters []map[string]any, responses map[string]any) map[string]any {
	op := map[string]any{
		"summary":               summary,
		"operationId":           operationID(summary),
		"tags":                  []string{tag},
		"responses":             responses,
		"x-aegisnas-visibility": "public",
	}
	if len(parameters) > 0 {
		op["parameters"] = parameters
	}
	return op
}

func openAPIOperationWithBody(summary, tag string, body map[string]any, responses map[string]any) map[string]any {
	op := openAPIOperation(summary, tag, nil, responses)
	if body != nil {
		op["requestBody"] = body
	}
	return op
}

func securedOperation(summary, tag string, roles []string, responses map[string]any) map[string]any {
	return securedOperationWithParameters(summary, tag, roles, nil, responses)
}

func securedOperationWithParameters(summary, tag string, roles []string, parameters []map[string]any, responses map[string]any) map[string]any {
	op := openAPIOperation(summary, tag, parameters, responses)
	op["security"] = []map[string]any{{"bearerAuth": []string{}}}
	op["x-aegisnas-roles"] = roles
	op["x-aegisnas-visibility"] = "authenticated"
	return op
}

func securedOperationWithBody(summary, tag string, roles []string, body map[string]any, responses map[string]any) map[string]any {
	return securedOperationWithParametersAndBody(summary, tag, roles, nil, body, responses)
}

func securedOperationWithParametersAndBody(summary, tag string, roles []string, parameters []map[string]any, body map[string]any, responses map[string]any) map[string]any {
	op := securedOperationWithParameters(summary, tag, roles, parameters, responses)
	if body != nil {
		op["requestBody"] = body
	}
	return op
}

func operationID(summary string) string {
	summary = strings.TrimSpace(strings.ToLower(summary))
	replacer := strings.NewReplacer(" ", "_", "/", "_", "-", "_", ".", "_", ":", "_")
	return "adminapi_" + replacer.Replace(summary)
}

func responseJSON(description string) map[string]any {
	return map[string]any{
		"description": description,
		"content": map[string]any{
			"application/json": map[string]any{
				"schema": map[string]any{
					"type":                 "object",
					"additionalProperties": true,
				},
			},
		},
	}
}

func responseBinary(mediaType, description string) map[string]any {
	return map[string]any{
		"description": description,
		"content": map[string]any{
			mediaType: map[string]any{
				"schema": map[string]any{
					"type":   "string",
					"format": "binary",
				},
			},
		},
	}
}

func responseXML(description string) map[string]any {
	return map[string]any{
		"description": description,
		"content": map[string]any{
			"application/xml": map[string]any{
				"schema": map[string]any{
					"type": "string",
				},
			},
		},
	}
}

func responseText(description string) map[string]any {
	return map[string]any{
		"description": description,
		"content": map[string]any{
			"text/plain": map[string]any{
				"schema": map[string]any{
					"type": "string",
				},
			},
		},
	}
}

func genericJSONObjectRequest(description string) map[string]any {
	return requestBody("application/json", map[string]any{
		"type":                 "object",
		"additionalProperties": true,
	}, true, description)
}

func multipartRequestBody(properties map[string]any, required []string, description string) map[string]any {
	schema := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return requestBody("multipart/form-data", schema, true, description)
}

func requestBody(mediaType string, schema map[string]any, required bool, description string) map[string]any {
	return map[string]any{
		"description": description,
		"required":    required,
		"content": map[string]any{
			mediaType: map[string]any{
				"schema": schema,
			},
		},
	}
}

func idParameter(name, description string) map[string]any {
	return map[string]any{
		"name":        name,
		"in":          "path",
		"required":    true,
		"description": description,
		"schema": map[string]any{
			"type": "string",
		},
	}
}

func queryEnumParameter(name, description string, values []string, required bool) map[string]any {
	schema := map[string]any{
		"type": "string",
	}
	if len(values) > 0 {
		schema["enum"] = values
	}
	return map[string]any{
		"name":        name,
		"in":          "query",
		"required":    required,
		"description": description,
		"schema":      schema,
	}
}

func queryStringParameter(name, description string, required bool) map[string]any {
	return map[string]any{
		"name":        name,
		"in":          "query",
		"required":    required,
		"description": description,
		"schema": map[string]any{
			"type": "string",
		},
	}
}

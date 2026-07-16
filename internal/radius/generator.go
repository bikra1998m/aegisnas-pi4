package radius

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/mab"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
)

// FreeRADIUSConfig bundles all generated configuration files.
type FreeRADIUSConfig struct {
	ClientsConf      string
	Dictionary       string
	VendorDictionary string
	EAPConf          string
	Users            string
	ModsLDAP         string
	ModsMSCHAP       string
	ModsSQL          string
	ProxyConf        string
	SitesDefault     string
	SitesInnerTunnel string
	RadSecSite       string
}

type generatedProxyRealm struct {
	Name       string
	PoolName   string
	StripRealm bool
}

const VendorDictionaryFilename = productconfigs.AegisNASVendorDictionaryFilename

// Generator creates FreeRADIUS configuration from the system config.
type Generator struct {
	cfg *config.Config
}

func NewGenerator(cfg *config.Config) *Generator {
	return &Generator{cfg: cfg}
}

// Generate produces all necessary FreeRADIUS configuration files.
func (g *Generator) Generate() (*FreeRADIUSConfig, error) {
	var out FreeRADIUSConfig
	var err error
	var clients []config.RadiusClient

	if db.DB != nil {
		clients, err = clientDefinitionsFromDB()
		if err != nil {
			if !isMissingRadiusClientsTable(err) {
				return nil, fmt.Errorf("clients generation: %w", err)
			}
			clients = append([]config.RadiusClient(nil), g.cfg.Radius.Clients...)
		}
	} else {
		clients = append([]config.RadiusClient(nil), g.cfg.Radius.Clients...)
	}
	clients = g.ensureBrokerClients(clients)
	clients, err = g.resolveClientSecrets(clients)
	if err != nil {
		return nil, fmt.Errorf("clients secret resolution: %w", err)
	}
	udpClients, radSecClients := splitClientDefinitions(clients)
	packetPolicy, _ := effectivePacketHardening(g.cfg)
	out.ClientsConf, err = renderClientDefinitions(udpClients, packetPolicy)
	if err != nil {
		return nil, fmt.Errorf("clients generation: %w", err)
	}

	out.Dictionary, err = g.renderDictionaryInclude()
	if err != nil {
		return nil, fmt.Errorf("dictionary generation: %w", err)
	}
	out.VendorDictionary, err = g.renderVendorDictionary()
	if err != nil {
		return nil, fmt.Errorf("vendor dictionary generation: %w", err)
	}

	// EAP configuration
	out.EAPConf, err = GenerateEAPConfig(g.cfg, g.cfg.Radius.CertDir)
	if err != nil {
		return nil, fmt.Errorf("eap generation: %w", err)
	}

	// Users file (static + dynamic users could be added later)
	out.Users, err = g.renderUsers()
	if err != nil {
		return nil, err
	}

	// LDAP module
	out.ModsLDAP, err = g.renderModsLDAP()
	if err != nil {
		return nil, err
	}

	// MSCHAP module
	out.ModsMSCHAP, err = g.renderModsMSCHAP()
	if err != nil {
		return nil, err
	}

	// SQL module
	out.ModsSQL, err = g.renderModsSQL()
	if err != nil {
		return nil, err
	}

	// Upstream proxy configuration
	out.ProxyConf, err = g.renderProxyConf()
	if err != nil {
		return nil, err
	}

	// Sites
	out.SitesDefault, err = g.renderSitesDefault()
	if err != nil {
		return nil, err
	}
	out.SitesInnerTunnel, err = g.renderSitesInnerTunnel()
	if err != nil {
		return nil, err
	}
	out.RadSecSite, err = g.renderRadSecSite(radSecClients)
	if err != nil {
		return nil, fmt.Errorf("radsec site generation: %w", err)
	}

	return &out, nil
}

func clientDefinitionsFromDB() ([]config.RadiusClient, error) {
	rows, err := db.DB.Query(`SELECT shortname, ipaddr, secret, COALESCE(secret_ref, ''), COALESCE(NULLIF(TRIM(nas_type), ''), 'other'),
		COALESCE(NULLIF(TRIM(transport), ''), 'udp'), COALESCE(radsec_certificate_cn, ''),
		COALESCE(radsec_certificate_issuer, ''), COALESCE(radsec_radius_v11, '')
		FROM radius_clients WHERE enabled = 1`)
	if isMissingRadiusClientSecretRefColumn(err) {
		return clientDefinitionsWithoutSecretRefFromDB()
	}
	if isMissingRadiusClientRadSecColumn(err) {
		return clientDefinitionsWithoutRadSecFromDB()
	}
	if isMissingRadiusClientNASTypeColumn(err) {
		return legacyClientDefinitionsFromDB()
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []config.RadiusClient
	for rows.Next() {
		var c config.RadiusClient
		if err := rows.Scan(&c.ShortName, &c.IP, &c.Secret, &c.SecretRef, &c.NASType, &c.Transport, &c.RadSecCertificateCN, &c.RadSecCertificateIssuer, &c.RadSecRadiusV11); err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func clientDefinitionsWithoutSecretRefFromDB() ([]config.RadiusClient, error) {
	rows, err := db.DB.Query(`SELECT shortname, ipaddr, secret, COALESCE(NULLIF(TRIM(nas_type), ''), 'other'),
		COALESCE(NULLIF(TRIM(transport), ''), 'udp'), COALESCE(radsec_certificate_cn, ''),
		COALESCE(radsec_certificate_issuer, ''), COALESCE(radsec_radius_v11, '')
		FROM radius_clients WHERE enabled = 1`)
	if isMissingRadiusClientRadSecColumn(err) {
		return clientDefinitionsWithoutRadSecFromDB()
	}
	if isMissingRadiusClientNASTypeColumn(err) {
		return legacyClientDefinitionsFromDB()
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []config.RadiusClient
	for rows.Next() {
		var c config.RadiusClient
		if err := rows.Scan(&c.ShortName, &c.IP, &c.Secret, &c.NASType, &c.Transport, &c.RadSecCertificateCN, &c.RadSecCertificateIssuer, &c.RadSecRadiusV11); err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func clientDefinitionsWithoutRadSecFromDB() ([]config.RadiusClient, error) {
	rows, err := db.DB.Query(`SELECT shortname, ipaddr, secret, COALESCE(NULLIF(TRIM(nas_type), ''), 'other') FROM radius_clients WHERE enabled = 1`)
	if isMissingRadiusClientNASTypeColumn(err) {
		return legacyClientDefinitionsFromDB()
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []config.RadiusClient
	for rows.Next() {
		var c config.RadiusClient
		if err := rows.Scan(&c.ShortName, &c.IP, &c.Secret, &c.NASType); err != nil {
			return nil, err
		}
		c.Transport = "udp"
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func legacyClientDefinitionsFromDB() ([]config.RadiusClient, error) {
	rows, err := db.DB.Query(`SELECT shortname, ipaddr, secret FROM radius_clients WHERE enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []config.RadiusClient
	for rows.Next() {
		var c config.RadiusClient
		if err := rows.Scan(&c.ShortName, &c.IP, &c.Secret); err != nil {
			return nil, err
		}
		c.NASType = "other"
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func renderClientDefinitions(clients []config.RadiusClient, packetPolicy PacketHardeningPolicy) (string, error) {
	messageAuthenticatorMode := FreeRADIUSMessageAuthenticatorMode(packetPolicy)
	renderClients := make([]radiusClientDefinition, 0, len(clients))
	for _, client := range clients {
		renderClients = append(renderClients, radiusClientDefinition{
			IP:                          client.IP,
			Secret:                      client.Secret,
			ShortName:                   client.ShortName,
			NASType:                     NormalizeClientNASType(client.NASType),
			RequireMessageAuthenticator: messageAuthenticatorMode,
		})
	}

	tmpl := `# -*- text -*-
# clients.conf – generated by aegis-radius
{{- range .}}
client {{ .ShortName }} {
	ipaddr = {{ .IP }}
	secret = {{ .Secret }}
	shortname = {{ .ShortName }}
	nastype = {{ .NASType }}
	require_message_authenticator = {{ .RequireMessageAuthenticator }}
}
{{- end}}
`
	var buf bytes.Buffer
	t := template.Must(template.New("clients").Parse(tmpl))
	err := t.Execute(&buf, renderClients)
	return buf.String(), err
}

func splitClientDefinitions(clients []config.RadiusClient) (udp, radsec []config.RadiusClient) {
	for _, client := range clients {
		if strings.EqualFold(strings.TrimSpace(client.Transport), "radsec") {
			radsec = append(radsec, client)
			continue
		}
		udp = append(udp, client)
	}
	return udp, radsec
}

type radiusClientDefinition struct {
	IP                          string
	Secret                      string
	ShortName                   string
	NASType                     string
	RequireMessageAuthenticator string
}

func (g *Generator) renderDictionaryInclude() (string, error) {
	return fmt.Sprintf(`# Local dictionary generated by aegis-radius.
# Product vendor attributes live in a separate AegisNAS dictionary file.
$INCLUDE %s
`, VendorDictionaryFilename), nil
}

func (g *Generator) renderVendorDictionary() (string, error) {
	if g.cfg == nil {
		return "", fmt.Errorf("configuration is required")
	}
	identity := productconfigs.AegisNASVendorIdentity()
	idSource := identity.IDSource
	if g.cfg.Radius.Vendor.ID != identity.ID {
		idSource = "config:radius.vendor.id"
	}

	attrs := EffectiveVendorAttributes(g.cfg.Radius.Vendor)
	data := struct {
		VendorName   string
		VendorID     int
		Enabled      bool
		IDSource     string
		Placeholder  bool
		IdentityMode string
		Organization string
		RecordSHA256 string
		RegistryURL  string
		ApplyURL     string
		InstallPath  string
		IncludeLine  string
		Attributes   []config.RadiusVendorAttribute
	}{
		VendorName:   strings.TrimSpace(g.cfg.Radius.Vendor.Name),
		VendorID:     g.cfg.Radius.Vendor.ID,
		Enabled:      g.cfg.Radius.Vendor.Enabled,
		IDSource:     idSource,
		Placeholder:  g.cfg.Radius.Vendor.ID == productconfigs.AegisNASPlaceholderVendorID,
		IdentityMode: strings.ToLower(strings.TrimSpace(g.cfg.Radius.Vendor.IdentityMode)),
		Organization: strings.TrimSpace(g.cfg.Radius.Vendor.AssignedOrganization),
		RecordSHA256: strings.TrimSpace(g.cfg.Radius.Vendor.AssignmentRecordSHA),
		RegistryURL:  identity.RegistryURL,
		ApplyURL:     identity.ApplyURL,
		InstallPath:  productconfigs.AegisNASVendorDictionaryInstallPath(ConfigDir()),
		IncludeLine:  "$INCLUDE " + VendorDictionaryFilename,
		Attributes:   attrs,
	}
	tmpl := `# AegisNAS product vendor dictionary generated by aegis-radius.
# Install path: {{ .InstallPath }}
# Include from local FreeRADIUS dictionary with: {{ .IncludeLine }}
# Vendor ID source: {{ .IDSource }}
# Identity mode: {{ .IdentityMode }}
{{- if not .Enabled }}
# Product VSA emission and parsing are disabled; the dictionary is installed for staged activation and packet inspection.
{{- end }}
{{- if .Placeholder }}
# WARNING: 55555 is a lab placeholder. Request an IANA Private Enterprise Number before production VSA use.
# Registry: {{ .RegistryURL }}
# Apply: {{ .ApplyURL }}
{{- else if eq .IdentityMode "production" }}
# IANA organization: {{ .Organization }}
# Assignment record SHA-256: {{ .RecordSHA256 }}
{{- else }}
# WARNING: this non-placeholder PEN has not completed the verified production identity workflow.
{{- end }}
VENDOR {{ .VendorName }} {{ .VendorID }}

BEGIN-VENDOR {{ .VendorName }}
{{- range .Attributes }}
ATTRIBUTE {{ .Name }} {{ .Number }} {{ .Type }}
{{- end }}
END-VENDOR {{ .VendorName }}
`
	var buf bytes.Buffer
	t := template.Must(template.New("dictionary").Parse(tmpl))
	err := t.Execute(&buf, data)
	return buf.String(), err
}

func (g *Generator) renderUsers() (string, error) {
	const header = `# files/authorize - local users (PAP and EAP-TTLS/PAP)
# Generated by aegis-radius. Passwords are bcrypt-compatible crypt hashes.

`
	var out strings.Builder
	out.WriteString(header)
	if db.DB == nil {
		return out.String(), nil
	}

	rows, err := db.DB.Query(`SELECT username, password_hash, role FROM local_users ORDER BY username`)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table: local_users") {
			if err := g.renderMABAuthorizeUsers(&out); err != nil {
				return "", err
			}
			return out.String(), nil
		}
		return "", fmt.Errorf("load local RADIUS users: %w", err)
	}
	type localUser struct {
		username     string
		passwordHash string
		role         string
	}
	var users []localUser
	for rows.Next() {
		var user localUser
		if err := rows.Scan(&user.username, &user.passwordHash, &user.role); err != nil {
			rows.Close()
			return "", err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", err
	}
	rows.Close()

	for _, user := range users {
		if strings.ContainsAny(user.username+user.passwordHash, "\r\n") {
			return "", fmt.Errorf("local RADIUS user %q contains an invalid newline", user.username)
		}
		attrs, err := GetReplyAttributes(user.username, user.role)
		if err != nil {
			return "", fmt.Errorf("build RADIUS reply for %s: %w", user.username, err)
		}
		items := BuildReplyAttributeItemsForVendorConfig(attrs, g.cfg.Radius.Vendor.CompatibilityPacks, g.cfg.Radius.Vendor)
		fmt.Fprintf(&out, "\"%s\" Crypt-Password := \"%s\"\n", escapeReplyValue(user.username), escapeReplyValue(user.passwordHash))
		for index, item := range items {
			if strings.ContainsAny(item.Name+item.Value, "\r\n") {
				return "", fmt.Errorf("RADIUS reply for local user %q contains an invalid newline", user.username)
			}
			separator := ","
			if index == len(items)-1 {
				separator = ""
			}
			if item.Quoted {
				fmt.Fprintf(&out, "\t%s := \"%s\"%s\n", item.Name, escapeReplyValue(item.Value), separator)
			} else {
				fmt.Fprintf(&out, "\t%s := %s%s\n", item.Name, item.Value, separator)
			}
		}
		out.WriteString("\n")
	}
	if err := g.renderMABAuthorizeUsers(&out); err != nil {
		return "", err
	}
	return out.String(), nil
}

func (g *Generator) renderMABAuthorizeUsers(out *strings.Builder) error {
	if out == nil || g == nil || g.cfg == nil || db.DB == nil {
		return nil
	}
	policy := mab.PolicyFromConfig(g.cfg)
	if !policy.Enabled {
		return nil
	}
	endpoints, err := db.ListMABEndpoints("", 50000)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return nil
		}
		return fmt.Errorf("load MAB endpoints: %w", err)
	}
	seenVariants := map[string]struct{}{}
	wroteHeader := false
	for _, endpoint := range endpoints {
		status := strings.ToLower(strings.TrimSpace(endpoint.Status))
		if status != "approved" && status != "quarantined" {
			continue
		}
		role := strings.TrimSpace(endpoint.Role)
		if role == "" && status == "quarantined" {
			role = policy.QuarantineRole
		}
		if role == "" {
			role = policy.DefaultRole
		}
		attrs, err := buildMABReplyAttributes(endpoint, role, status)
		if err != nil {
			return err
		}
		items := BuildReplyAttributeItemsForVendorConfig(attrs, g.cfg.Radius.Vendor.CompatibilityPacks, g.cfg.Radius.Vendor)
		variants := mab.MACVariants(endpoint.MAC, policy.MACFormats)
		for _, variant := range variants {
			if strings.ContainsAny(variant, "\r\n") {
				return fmt.Errorf("MAB endpoint %q generated an invalid username variant", endpoint.MAC)
			}
			if _, exists := seenVariants[variant]; exists {
				continue
			}
			seenVariants[variant] = struct{}{}
			if !wroteHeader {
				out.WriteString("# MAC Authentication Bypass endpoints (NAS-0017)\n")
				out.WriteString("# Known endpoint MAC variants are accepted without relying on vendor-specific password formatting.\n\n")
				wroteHeader = true
			}
			fmt.Fprintf(out, "\"%s\" Auth-Type := Accept\n", escapeReplyValue(variant))
			for index, item := range items {
				if strings.ContainsAny(item.Name+item.Value, "\r\n") {
					return fmt.Errorf("MAB reply for endpoint %q contains an invalid newline", endpoint.MAC)
				}
				separator := ","
				if index == len(items)-1 {
					separator = ""
				}
				if item.Quoted {
					fmt.Fprintf(out, "\t%s := \"%s\"%s\n", item.Name, escapeReplyValue(item.Value), separator)
				} else {
					fmt.Fprintf(out, "\t%s := %s%s\n", item.Name, item.Value, separator)
				}
			}
			out.WriteString("\n")
		}
	}
	return nil
}

func buildMABReplyAttributes(endpoint db.MABEndpoint, role, status string) (*ReplyAttributes, error) {
	var attrs *ReplyAttributes
	var err error
	if strings.TrimSpace(role) != "" {
		attrs, err = GetReplyAttributes(endpoint.MAC, role)
		if err != nil {
			return nil, fmt.Errorf("build MAB reply for %s role %s: %w", endpoint.MAC, role, err)
		}
	} else {
		attrs = &ReplyAttributes{}
	}
	attrs.Role = strings.TrimSpace(role)
	if endpoint.VLAN > 0 {
		attrs.VLAN = endpoint.VLAN
		attrs.TunnelType = "VLAN"
		attrs.TunnelMediumType = "IEEE-802"
		attrs.TunnelPrivateGroupID = fmt.Sprintf("%d", endpoint.VLAN)
	}
	if strings.TrimSpace(endpoint.BandwidthProfile) != "" {
		attrs.BandwidthProfile = strings.TrimSpace(endpoint.BandwidthProfile)
		var down, up int
		if err := db.DB.QueryRow(`SELECT download_rate_kbps, upload_rate_kbps FROM bandwidth_profiles WHERE name = ?`, attrs.BandwidthProfile).Scan(&down, &up); err == nil {
			attrs.MikrotikRateLimit = fmt.Sprintf("%dk/%dk", down, up)
			attrs.WISPrBandwidthMaxDown = down
			attrs.WISPrBandwidthMaxUp = up
		}
	}
	if strings.TrimSpace(endpoint.ACLPolicyName) != "" {
		loaded, err := ApplyStoredACLPolicy(attrs, endpoint.ACLPolicyName)
		if err != nil {
			return nil, err
		}
		if !loaded {
			return nil, fmt.Errorf("ACL policy %s assigned to MAB endpoint %s is missing or disabled", endpoint.ACLPolicyName, endpoint.MAC)
		}
	}
	attrs.Tenant = strings.TrimSpace(endpoint.Tenant)
	attrs.DeviceGroup = strings.TrimSpace(endpoint.DeviceGroup)
	attrs.HasQuarantine = status == "quarantined"
	attrs.Quarantine = status == "quarantined"
	return attrs, nil
}

func isMissingRadiusClientsTable(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such table: radius_clients")
}

func isMissingRadiusClientNASTypeColumn(err error) bool {
	if err == nil {
		return false
	}
	normalized := strings.ToLower(err.Error())
	return strings.Contains(normalized, "no such column") && strings.Contains(normalized, "nas_type")
}

func isMissingRadiusClientRadSecColumn(err error) bool {
	if err == nil {
		return false
	}
	normalized := strings.ToLower(err.Error())
	return strings.Contains(normalized, "no such column") &&
		(strings.Contains(normalized, "transport") || strings.Contains(normalized, "radsec_"))
}

func isMissingRadiusClientSecretRefColumn(err error) bool {
	if err == nil {
		return false
	}
	normalized := strings.ToLower(err.Error())
	return strings.Contains(normalized, "no such column") && strings.Contains(normalized, "secret_ref")
}

func (g *Generator) ensureBrokerClients(existing []config.RadiusClient) []config.RadiusClient {
	clients := append([]config.RadiusClient(nil), existing...)
	ensure := func(ip, shortName string) {
		for i, client := range clients {
			if client.IP != ip {
				continue
			}
			clients[i].Secret = g.cfg.Radius.Secret
			clients[i].SecretRef = g.cfg.Radius.SecretRef
			if strings.TrimSpace(clients[i].ShortName) == "" {
				clients[i].ShortName = shortName
			}
			if strings.TrimSpace(clients[i].NASType) == "" {
				clients[i].NASType = "other"
			}
			return
		}
		clients = append(clients, config.RadiusClient{
			IP:        ip,
			Secret:    g.cfg.Radius.Secret,
			SecretRef: g.cfg.Radius.SecretRef,
			ShortName: shortName,
			NASType:   "other",
			Transport: "udp",
		})
	}

	ensure("127.0.0.1", "aegisnas-local-broker")
	ensure("::1", "aegisnas-local-broker-v6")
	return clients
}

func (g *Generator) resolveClientSecrets(clients []config.RadiusClient) ([]config.RadiusClient, error) {
	resolver := secrets.NewResolver(secrets.OptionsFromConfig(g.cfg))
	resolved := append([]config.RadiusClient(nil), clients...)
	for i := range resolved {
		transport := strings.ToLower(strings.TrimSpace(resolved[i].Transport))
		if transport == "" {
			transport = "udp"
		}
		if transport == "radsec" {
			resolved[i].Secret = "radsec"
			resolved[i].SecretRef = ""
			continue
		}
		secret, err := secrets.ResolveConfiguredSecret(context.Background(), resolver, fmt.Sprintf("radius.clients[%d].secret", i), resolved[i].Secret, resolved[i].SecretRef)
		if err != nil {
			return nil, err
		}
		resolved[i].Secret = secret
		resolved[i].SecretRef = ""
	}
	return resolved, nil
}

func normalizeRadSecPSKHexPhrase(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 32 || len(value) > 512 || len(value)%2 != 0 {
		return "", fmt.Errorf("TLS-PSK secret must be an even-length hex string between 32 and 512 characters")
	}
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return "", fmt.Errorf("TLS-PSK secret must contain only hexadecimal characters")
	}
	return value, nil
}

func (g *Generator) renderModsLDAP() (string, error) {
	ldap, enabled := g.effectiveLDAPModuleConfig()
	if !enabled {
		return "# LDAP disabled\n", nil
	}
	secretField := "ldap.bind_password"
	if !g.cfg.LDAP.Enabled && g.cfg.ActiveDirectory.Enabled {
		secretField = "active_directory.bind_password"
	}
	password, err := secrets.ResolveConfiguredSecret(context.Background(), secrets.NewResolver(secrets.OptionsFromConfig(g.cfg)), secretField, ldap.BindPassword, ldap.BindPasswordRef)
	if err != nil {
		return "", err
	}
	ldap.BindPassword = password
	tmpl := `# mods-enabled/ldap
ldap {
	server = '{{ .LDAP.URL }}'
	port = 389
	identity = '{{ .LDAP.BindDN }}'
	password = '{{ .LDAP.BindPassword }}'
	base_dn = '{{ .LDAP.BaseDN }}'

	user {
		base_dn = "ou=users,${..base_dn}"
		filter = "{{ .LDAP.UserFilter }}"
	}
	group {
		base_dn = "ou=groups,${..base_dn}"
		membership_filter = "{{ .LDAP.GroupFilter }}"
	}
	options {
		chase_referrals = yes
		rebind = yes
		net_timeout = 5
	}
}
`
	var buf bytes.Buffer
	t := template.Must(template.New("ldap").Parse(tmpl))
	err = t.Execute(&buf, struct{ LDAP config.LDAPConfig }{LDAP: ldap})
	return buf.String(), err
}

func (g *Generator) effectiveLDAPModuleConfig() (config.LDAPConfig, bool) {
	if g.cfg.LDAP.Enabled {
		return g.cfg.LDAP, true
	}
	if !g.cfg.ActiveDirectory.Enabled {
		return config.LDAPConfig{}, false
	}
	ad := config.EffectiveActiveDirectoryConfig(g.cfg.ActiveDirectory)
	return config.LDAPConfig{
		Enabled:         true,
		URL:             ad.LDAPURL,
		BaseDN:          ad.BaseDN,
		BindDN:          ad.BindDN,
		BindPassword:    ad.BindPassword,
		BindPasswordRef: ad.BindPasswordRef,
		UserFilter:      ad.UserFilter,
		GroupFilter:     ad.GroupFilter,
	}, true
}

func (g *Generator) ldapModuleEnabled() bool {
	_, enabled := g.effectiveLDAPModuleConfig()
	return enabled
}

func (g *Generator) renderModsMSCHAP() (string, error) {
	ad := config.EffectiveActiveDirectoryConfig(g.cfg.ActiveDirectory)
	if !ad.Enabled || !ad.Winbind.Enabled {
		return `# mods-enabled/mschap
mschap {
	use_mppe = yes
	require_encryption = yes
	require_strong = yes
	with_ntdomain_hack = yes
}
`, nil
	}
	domain := strings.TrimSpace(ad.NetBIOSDomain)
	if domain == "" {
		domain = strings.TrimSpace(ad.Domain)
	}
	if domain == "" {
		return "", fmt.Errorf("active_directory.winbind requires domain or netbios_domain for mschap generation")
	}
	ntlmAuthPath := strings.TrimSpace(ad.Winbind.NTLMAuthPath)
	if ntlmAuthPath == "" {
		ntlmAuthPath = "/usr/bin/ntlm_auth"
	}
	if strings.ContainsAny(domain+ntlmAuthPath, "\r\n\"") {
		return "", fmt.Errorf("active_directory winbind mschap settings contain invalid characters")
	}
	tmpl := `# mods-enabled/mschap
mschap {
	use_mppe = yes
	require_encryption = yes
	require_strong = yes
	with_ntdomain_hack = yes
	ntlm_auth = "{{ .NTLMAuthPath }} --request-nt-key --domain={{ .Domain }} --username=%{%{Stripped-User-Name}:-%{%{mschap:User-Name}:-%{%{User-Name}:-None}}} --challenge=%{%{mschap:Challenge}:-00} --nt-response=%{%{mschap:NT-Response}:-00}"
}
`
	var buf bytes.Buffer
	t := template.Must(template.New("mschap").Parse(tmpl))
	err := t.Execute(&buf, map[string]string{
		"Domain":       escapeReplyValue(domain),
		"NTLMAuthPath": escapeReplyValue(ntlmAuthPath),
	})
	return buf.String(), err
}

func (g *Generator) renderModsSQL() (string, error) {
	if strings.EqualFold(strings.TrimSpace(g.cfg.Database.Backend), "postgres") || strings.EqualFold(strings.TrimSpace(g.cfg.Database.Backend), "postgresql") {
		return g.renderModsPostgreSQL()
	}
	tmpl := `# mods-enabled/sql
sql {
	dialect = "sqlite"
	driver = "rlm_sql_sqlite"
	sqlite {
		filename = "{{ .Database.Path }}"
		busy_timeout = 200
	}

	radius_db = "radius"

	accounting {
		reference = "%{tolower:type.%{Acct-Status-Type}}"
	}

	postauth {
		reference = ".query"
	}
}
`
	var buf bytes.Buffer
	t := template.Must(template.New("sql").Parse(tmpl))
	err := t.Execute(&buf, g.cfg)
	return buf.String(), err
}

func (g *Generator) renderModsPostgreSQL() (string, error) {
	dsn := strings.TrimSpace(g.cfg.Database.DSN)
	if ref := strings.TrimSpace(g.cfg.Database.DSNRef); ref != "" {
		resolved, err := secrets.ResolveConfiguredSecret(context.Background(), secrets.NewResolver(secrets.OptionsFromConfig(g.cfg)), "database.dsn", "", ref)
		if err != nil {
			return "", err
		}
		dsn = strings.TrimSpace(resolved)
	}
	parsed, err := parsePostgreSQLURLDSN(dsn)
	if err != nil {
		return "", err
	}
	tmpl := `# mods-enabled/sql
sql {
	dialect = "postgresql"
	driver = "rlm_sql_postgresql"
	server = "{{ .Host }}"
	port = {{ .Port }}
	login = "{{ .User }}"
	password = "{{ .Password }}"
	radius_db = "{{ .Database }}"

	accounting {
		reference = "%{tolower:type.%{Acct-Status-Type}}"
	}

	postauth {
		reference = ".query"
	}
}
`
	var buf bytes.Buffer
	t := template.Must(template.New("sql-postgresql").Parse(tmpl))
	err = t.Execute(&buf, parsed)
	return buf.String(), err
}

type postgreSQLSQLModuleDSN struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
}

func parsePostgreSQLURLDSN(raw string) (postgreSQLSQLModuleDSN, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return postgreSQLSQLModuleDSN{}, fmt.Errorf("database PostgreSQL DSN must use a postgres:// URL for FreeRADIUS SQL generation")
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return postgreSQLSQLModuleDSN{}, fmt.Errorf("database PostgreSQL DSN scheme %q is not supported", parsed.Scheme)
	}
	port := 5432
	if parsed.Port() != "" {
		value, err := strconv.Atoi(parsed.Port())
		if err != nil || value < 1 || value > 65535 {
			return postgreSQLSQLModuleDSN{}, fmt.Errorf("database PostgreSQL DSN port is invalid")
		}
		port = value
	}
	user := ""
	password := ""
	if parsed.User != nil {
		user = parsed.User.Username()
		password, _ = parsed.User.Password()
	}
	databaseName := strings.Trim(strings.TrimSpace(parsed.Path), "/")
	if parsed.Hostname() == "" || user == "" || databaseName == "" {
		return postgreSQLSQLModuleDSN{}, fmt.Errorf("database PostgreSQL DSN must include host, user, and database name")
	}
	return postgreSQLSQLModuleDSN{
		Host:     parsed.Hostname(),
		Port:     port,
		User:     user,
		Password: password,
		Database: databaseName,
	}, nil
}

func (g *Generator) renderProxyConf() (string, error) {
	if !g.cfg.Radius.Upstream.Enabled {
		return "# Upstream RADIUS proxy disabled\n", nil
	}

	transportPolicy := BuildTransportPolicyReport(g.cfg)
	if transportPolicy.Status == "blocked" {
		return "", fmt.Errorf("transport downgrade policy blocked proxy generation: %s", transportPolicy.Message)
	}

	routes, err := EffectiveProxyRoutes(g.cfg)
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "", fmt.Errorf("radius upstream is enabled but no proxy routes are available")
	}

	type proxyHomeServer struct {
		Name              string
		Address           string
		AuthPort          int
		AcctPort          int
		Secret            string
		Transport         string
		RadSec            config.RadiusRadSecPeerConfig
		PSKIdentity       string
		PSKHexPhrase      string
		StatusCheck       string
		ResponseWindow    int
		ZombiePeriod      int
		ReviveInterval    int
		CheckInterval     int
		NumAnswersToAlive int
	}
	type proxyPool struct {
		Name         string
		PoolStrategy string
		HomeServers  []string
	}

	homeServers := make([]proxyHomeServer, 0)
	pools := make([]proxyPool, 0, len(routes))
	realms := make([]generatedProxyRealm, 0, len(routes))
	seenRealm := make(map[string]struct{})
	resolver := secrets.NewResolver(secrets.OptionsFromConfig(g.cfg))
	for _, route := range routes {
		if len(route.Servers) == 0 {
			return "", fmt.Errorf("proxy route %q has no home servers", route.Name)
		}
		pool := proxyPool{Name: route.PoolName, PoolStrategy: route.PoolStrategy}
		for _, server := range route.Servers {
			authPort := server.AuthPort
			if authPort == 0 {
				authPort = g.cfg.Radius.AuthPort
			}
			acctPort := server.AcctPort
			if acctPort == 0 {
				acctPort = g.cfg.Radius.AcctPort
			}
			transport := strings.ToLower(strings.TrimSpace(server.Transport))
			if transport == "" {
				transport = "udp"
			}
			if transport == "radsec" {
				authPort = server.RadSec.Port
				acctPort = server.RadSec.Port
			}
			secret := server.Secret
			if transport == "udp" {
				resolvedSecret, err := secrets.ResolveConfiguredSecret(context.Background(), resolver, "radius.upstream.servers."+server.Name+".secret", server.Secret, server.SecretRef)
				if err != nil {
					return "", err
				}
				secret = resolvedSecret
			}
			pskHexPhrase := ""
			pskIdentity := ""
			if transport == "radsec" && server.RadSec.PSK.Enabled {
				selectedPSK, err := SelectRadSecPSK(server.RadSec.PSK, time.Now().UTC())
				if err != nil {
					return "", fmt.Errorf("radius.upstream.servers.%s.radsec.psk: %w", server.Name, err)
				}
				pskIdentity = selectedPSK.Identity
				resolved, err := secrets.ResolveConfiguredSecret(context.Background(), resolver, "radius.upstream.servers."+server.Name+".radsec.psk.secret_ref", "", selectedPSK.SecretRef)
				if err != nil {
					return "", err
				}
				pskHexPhrase, err = normalizeRadSecPSKHexPhrase(resolved)
				if err != nil {
					return "", fmt.Errorf("radius.upstream.servers.%s.radsec.psk.secret_ref: %w", server.Name, err)
				}
			}

			homeServerName := strings.TrimSpace(server.Name)
			if route.Name != "legacy-default" {
				homeServerName = route.PoolName + "_" + freeRADIUSIdentifier(server.Name)
			}
			pool.HomeServers = append(pool.HomeServers, homeServerName)
			homeServers = append(homeServers, proxyHomeServer{
				Name:              homeServerName,
				Address:           server.Address,
				AuthPort:          authPort,
				AcctPort:          acctPort,
				Secret:            secret,
				Transport:         transport,
				RadSec:            server.RadSec,
				PSKIdentity:       pskIdentity,
				PSKHexPhrase:      pskHexPhrase,
				StatusCheck:       route.StatusCheck,
				ResponseWindow:    g.cfg.Radius.Upstream.ResponseWindow,
				ZombiePeriod:      g.cfg.Radius.Upstream.ZombiePeriod,
				ReviveInterval:    g.cfg.Radius.Upstream.ReviveInterval,
				CheckInterval:     g.cfg.Radius.Upstream.CheckInterval,
				NumAnswersToAlive: g.cfg.Radius.Upstream.NumAnswersToAlive,
			})
		}
		pools = append(pools, pool)
		for _, realm := range route.MatchRealms {
			addProxyRealm(&realms, seenRealm, generatedProxyRealm{Name: realm, PoolName: route.PoolName, StripRealm: route.StripRealm})
		}
		if route.Default {
			addProxyRealm(&realms, seenRealm, generatedProxyRealm{Name: "DEFAULT", PoolName: route.PoolName, StripRealm: route.StripRealm})
			addProxyRealm(&realms, seenRealm, generatedProxyRealm{Name: "NULL", PoolName: route.PoolName, StripRealm: route.StripRealm})
		}
	}

	packetPolicy, _ := effectivePacketHardening(g.cfg)
	data := struct {
		HomeServers                 []proxyHomeServer
		Pools                       []proxyPool
		Realms                      []generatedProxyRealm
		RequireMessageAuthenticator string
	}{
		HomeServers:                 homeServers,
		Pools:                       pools,
		Realms:                      realms,
		RequireMessageAuthenticator: FreeRADIUSMessageAuthenticatorMode(packetPolicy),
	}

	tmpl := `# proxy.conf - generated by aegis-radius
# Upstream AAA proxy mode is enabled. Access-Request and Accounting-Request
# packets are forwarded to the configured home server pool.
proxy server {
	default_fallback = no
}

{{- range .HomeServers }}
home_server {{ .Name }} {
	type = auth+acct
	ipaddr = {{ .Address }}
	port = {{ .AuthPort }}
	{{- if eq .Transport "radsec" }}
	proto = tcp
	secret = radsec
	hostname = {{ .RadSec.ServerName }}
	nonblock = yes
	tls {
		{{- if .RadSec.PSK.Enabled }}
		psk_identity = "{{ .PSKIdentity }}"
		psk_hexphrase = "{{ .PSKHexPhrase }}"
		{{- else }}
		certificate_file = {{ .RadSec.CertificateFile }}
		private_key_file = {{ .RadSec.PrivateKeyFile }}
		{{- if .RadSec.PrivateKeyPasswordEnv }}
		private_key_password = $ENV{ {{- .RadSec.PrivateKeyPasswordEnv -}} }
		{{- end }}
		{{- if .RadSec.CAFile }}
		ca_file = {{ .RadSec.CAFile }}
		{{- end }}
		{{- if .RadSec.CAPath }}
		ca_path = {{ .RadSec.CAPath }}
		{{- end }}
		check_crl = {{ if .RadSec.CheckCRL }}yes{{ else }}no{{ end }}
		{{- end }}
		cipher_list = "{{ .RadSec.CipherList }}"
		tls_min_version = "{{ .RadSec.TLSMinVersion }}"
		tls_max_version = "{{ .RadSec.TLSMaxVersion }}"
		{{- if and (ne .RadSec.RadiusV11 "") (ne .RadSec.RadiusV11 "forbid") }}
		radiusv1_1 = {{ .RadSec.RadiusV11 }}
		{{- end }}
	}
	limit {
		max_connections = {{ .RadSec.MaxConnections }}
		max_requests = {{ .RadSec.MaxRequests }}
		lifetime = {{ .RadSec.LifetimeSeconds }}
		idle_timeout = {{ .RadSec.IdleTimeoutSeconds }}
	}
	{{- else }}
	acctport = {{ .AcctPort }}
	secret = {{ .Secret }}
	{{- end }}
	response_window = {{ .ResponseWindow }}
	zombie_period = {{ .ZombiePeriod }}
	require_message_authenticator = {{ $.RequireMessageAuthenticator }}
	{{- if eq .StatusCheck "status-server" }}
	status_check = status-server
	check_interval = {{ .CheckInterval }}
	num_answers_to_alive = {{ .NumAnswersToAlive }}
	{{- else }}
	status_check = none
	revive_interval = {{ .ReviveInterval }}
	{{- end }}
}
{{- end }}
{{- range .Pools }}
home_server_pool {{ .Name }} {
	type = {{ .PoolStrategy }}
{{- range .HomeServers }}
	home_server = {{ . }}
{{- end }}
}

{{- end }}
{{- range .Realms }}
realm {{ .Name }} {
	pool = {{ .PoolName }}
	{{- if .StripRealm }}
	strip
	{{- else }}
	nostrip
	{{- end }}
}
{{- end }}
`
	var buf bytes.Buffer
	t := template.Must(template.New("proxy").Parse(tmpl))
	err = t.Execute(&buf, data)
	return buf.String(), err
}

func addProxyRealm(realms *[]generatedProxyRealm, seen map[string]struct{}, realm generatedProxyRealm) {
	realm.Name = strings.TrimSpace(realm.Name)
	if realm.Name == "" {
		return
	}
	key := strings.ToLower(realm.Name)
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*realms = append(*realms, realm)
}

func (g *Generator) renderRadSecSite(clients []config.RadiusClient) (string, error) {
	if !g.cfg.Radius.RadSec.Enabled {
		return "# RadSec listener disabled\n", nil
	}

	data := struct {
		Config  config.RadiusRadSecConfig
		Clients []config.RadiusClient
	}{Config: g.cfg.Radius.RadSec, Clients: clients}
	tmpl := `# sites-enabled/aegis-radsec - generated by aegis-radius
# RFC 6614 RADIUS/TLS listener. Mutual X.509 authentication is mandatory.
listen {
	ipaddr = {{ .Config.ListenAddress }}
	port = {{ .Config.Port }}
	type = auth+acct+coa
	proto = tcp
	virtual_server = default
	clients = aegis_radsec_clients
	nonblock = yes
	check_client_connections = yes
	limit {
		max_connections = {{ .Config.MaxConnections }}
		lifetime = {{ .Config.LifetimeSeconds }}
		idle_timeout = {{ .Config.IdleTimeoutSeconds }}
	}
	tls {
		certificate_file = {{ .Config.CertificateFile }}
		private_key_file = {{ .Config.PrivateKeyFile }}
		{{- if .Config.PrivateKeyPasswordEnv }}
		private_key_password = $ENV{ {{- .Config.PrivateKeyPasswordEnv -}} }
		{{- end }}
		{{- if .Config.CAFile }}
		ca_file = {{ .Config.CAFile }}
		{{- end }}
		{{- if .Config.CAPath }}
		ca_path = {{ .Config.CAPath }}
		{{- end }}
		require_client_cert = yes
		check_cert_cn = %{client:shortname}
		check_crl = {{ if .Config.CheckCRL }}yes{{ else }}no{{ end }}
		check_all_crl = {{ if .Config.CheckAllCRL }}yes{{ else }}no{{ end }}
		ca_path_reload_interval = {{ .Config.CAPathReloadInterval }}
		cipher_list = "{{ .Config.CipherList }}"
		cipher_server_preference = yes
		tls_min_version = "{{ .Config.TLSMinVersion }}"
		tls_max_version = "{{ .Config.TLSMaxVersion }}"
		{{- if and (ne .Config.RadiusV11 "") (ne .Config.RadiusV11 "forbid") }}
		radiusv1_1 = {{ .Config.RadiusV11 }}
		{{- end }}
	}
}

clients aegis_radsec_clients {
{{- range .Clients }}
	client {{ .ShortName }} {
		ipaddr = {{ .IP }}
		secret = radsec
		proto = tls
		shortname = {{ .RadSecCertificateCN }}
		nastype = {{ .NASType }}
		{{- if .RadSecCertificateIssuer }}
		aegis_radsec_issuer = "{{ .RadSecCertificateIssuer }}"
		{{- end }}
		{{- if and (ne .RadSecRadiusV11 "") (ne .RadSecRadiusV11 "forbid") }}
		radiusv1_1 = {{ .RadSecRadiusV11 }}
		{{- end }}
		limit {
			max_connections = {{ $.Config.MaxConnections }}
			lifetime = {{ $.Config.LifetimeSeconds }}
			idle_timeout = {{ $.Config.IdleTimeoutSeconds }}
		}
	}
{{- end }}
}
`
	var buf bytes.Buffer
	t := template.Must(template.New("radsec-site").Parse(tmpl))
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (g *Generator) renderSitesDefault() (string, error) {
	tmpl := `# sites-enabled/default
server default {
	listen {
		type = auth
		ipaddr = *
		port = {{ .Radius.AuthPort }}
	}
	listen {
		type = acct
		ipaddr = *
		port = {{ .Radius.AcctPort }}
	}

	authorize {
		{{- if .Radius.RadSec.Enabled }}
		Autz-Type New-TLS-Connection {
			if ("%{client:aegis_radsec_issuer}" && ("%{listen:TLS-Client-Cert-Issuer}" != "%{client:aegis_radsec_issuer}")) {
				reject
			}
			ok
		}
		{{- end }}
		preprocess
		chap
		mschap
		digest
		suffix
		{{- if .Radius.Upstream.Enabled }}
		{{- if .ProxyDefaultRealm }}
		if (!&control:Proxy-To-Realm) {
			update control {
				Proxy-To-Realm := "{{ .ProxyDefaultRealm }}"
			}
		}
		{{- end }}
		{{- else }}
		eap {
			ok = return
		}
		files
		{{- if .LDAPModuleEnabled }}
		ldap
		{{- end }}
		pap
		{{- end }}
	}

	authenticate {
		Auth-Type PAP {
			pap
		}
		Auth-Type CHAP {
			chap
		}
		Auth-Type MS-CHAP {
			mschap
		}
		eap
	}

	preacct {
		preprocess
		acct_unique
		suffix
		files
		{{- if .Radius.Upstream.Enabled }}
		{{- if .ProxyDefaultRealm }}
		if (!&control:Proxy-To-Realm) {
			update control {
				Proxy-To-Realm := "{{ .ProxyDefaultRealm }}"
			}
		}
		{{- end }}
		{{- end }}
	}

	accounting {
		detail
		unix
		sql
		exec
	}

	session {
		radutmp
	}

	post-auth {
		exec
		reply_log
	}

	pre-proxy {
{{ .ProxyRequestPolicy }}
	}

	post-proxy {
{{ .ProxyResponsePolicy }}
	}
}
`
	var buf bytes.Buffer
	t := template.Must(template.New("default").Parse(tmpl))
	proxyRequestPolicy, err := FreeRADIUSProxyPolicyUnlang(g.cfg, "proxy-request")
	if err != nil {
		return "", err
	}
	proxyResponsePolicy, err := FreeRADIUSProxyPolicyUnlang(g.cfg, "proxy-reply")
	if err != nil {
		return "", err
	}
	data := struct {
		*config.Config
		ProxyDefaultRealm   string
		ProxyRequestPolicy  string
		ProxyResponsePolicy string
		LDAPModuleEnabled   bool
	}{
		Config:              g.cfg,
		ProxyDefaultRealm:   DefaultProxyRealm(g.cfg),
		ProxyRequestPolicy:  proxyRequestPolicy,
		ProxyResponsePolicy: proxyResponsePolicy,
		LDAPModuleEnabled:   g.ldapModuleEnabled(),
	}
	err = t.Execute(&buf, data)
	return buf.String(), err
}

func (g *Generator) renderSitesInnerTunnel() (string, error) {
	tmpl := `# sites-enabled/inner-tunnel
server inner-tunnel {
	listen {
		ipaddr = 127.0.0.1
		port = 18120
		type = auth
	}

	authorize {
		filter_username
		preprocess
		chap
		mschap
		suffix
		{{- if .Radius.Upstream.Enabled }}
		{{- if .ProxyDefaultRealm }}
		if (!&control:Proxy-To-Realm) {
			update control {
				Proxy-To-Realm := "{{ .ProxyDefaultRealm }}"
			}
		}
		{{- end }}
		{{- else }}
		update control {
			&Proxy-To-Realm := LOCAL
		}
		eap {
			ok = return
		}
		files
		{{- if .LDAPModuleEnabled }}
		ldap
		{{- end }}
		pap
		{{- end }}
	}

	authenticate {
		Auth-Type PAP {
			pap
		}
		Auth-Type CHAP {
			chap
		}
		Auth-Type MS-CHAP {
			mschap
		}
		eap
	}

	session {
		radutmp
	}

	post-auth {
		Post-Auth-Type REJECT {
			attr_filter.access_reject
		}
	}

	pre-proxy {
{{ .ProxyRequestPolicy }}
	}

	post-proxy {
{{ .ProxyResponsePolicy }}
	}
}
`
	var buf bytes.Buffer
	t := template.Must(template.New("inner-tunnel").Parse(tmpl))
	proxyRequestPolicy, err := FreeRADIUSProxyPolicyUnlang(g.cfg, "proxy-request")
	if err != nil {
		return "", err
	}
	proxyResponsePolicy, err := FreeRADIUSProxyPolicyUnlang(g.cfg, "proxy-reply")
	if err != nil {
		return "", err
	}
	data := struct {
		*config.Config
		ProxyDefaultRealm   string
		ProxyRequestPolicy  string
		ProxyResponsePolicy string
		LDAPModuleEnabled   bool
	}{
		Config:              g.cfg,
		ProxyDefaultRealm:   DefaultProxyRealm(g.cfg),
		ProxyRequestPolicy:  proxyRequestPolicy,
		ProxyResponsePolicy: proxyResponsePolicy,
		LDAPModuleEnabled:   g.ldapModuleEnabled(),
	}
	err = t.Execute(&buf, data)
	return buf.String(), err
}

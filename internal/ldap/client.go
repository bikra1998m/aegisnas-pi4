package ldap

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

type Client struct {
	conn   *ldap.Conn
	cfg    *config.LDAPConfig
	logger *zap.Logger
}

// NewClient creates a new LDAP client and connects using the service account.
func NewClient(cfg *config.LDAPConfig, logger *zap.Logger) (*Client, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("LDAP is disabled")
	}
	var conn *ldap.Conn
	var err error
	if strings.HasPrefix(cfg.URL, "ldaps://") {
		conn, err = ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))
	} else {
		conn, err = ldap.DialURL(cfg.URL)
	}
	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}
	if cfg.BindDN != "" && cfg.BindPassword != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ldap bind: %w", err)
		}
	}
	return &Client{conn: conn, cfg: cfg, logger: logger}, nil
}

// Close closes the LDAP connection.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// Authenticate checks user credentials against LDAP.
func (c *Client) Authenticate(username, password string) (bool, error) {
	if !c.cfg.Enabled {
		return false, fmt.Errorf("LDAP disabled")
	}
	userDN, err := c.findUserDN(username)
	if err != nil {
		return false, err
	}
	userConn, err := ldap.DialURL(c.cfg.URL)
	if err != nil {
		return false, err
	}
	defer userConn.Close()
	if err := userConn.Bind(userDN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (c *Client) findUserDN(username string) (string, error) {
	filter := strings.ReplaceAll(c.cfg.UserFilter, "%s", ldap.EscapeFilter(username))
	searchReq := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)
	sr, err := c.conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("user search failed: %w", err)
	}
	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("user not found")
	}
	return sr.Entries[0].DN, nil
}

// GetUserGroups retrieves group names for a user.
func (c *Client) GetUserGroups(username string) ([]string, error) {
	if !c.cfg.Enabled {
		return nil, nil
	}
	userDN, err := c.findUserDN(username)
	if err != nil {
		return nil, err
	}
	filter := c.cfg.GroupFilter
	if filter == "" {
		filter = fmt.Sprintf("(|(memberUid=%s)(member=%s))", ldap.EscapeFilter(username), ldap.EscapeFilter(userDN))
	} else {
		filter = strings.ReplaceAll(filter, "%s", ldap.EscapeFilter(username))
		filter = strings.ReplaceAll(filter, "%D", ldap.EscapeFilter(userDN))
	}
	searchReq := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"cn"},
		nil,
	)
	sr, err := c.conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("group search failed: %w", err)
	}
	var groups []string
	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}

// GetRoleForGroups maps a list of group names to a local role using the database mapping.
func GetRoleForGroups(groups []string) (string, error) {
	if len(groups) == 0 {
		return "", nil
	}
	var configJSON string
	err := db.DB.QueryRow(`SELECT config FROM identity_sources WHERE type = 'ldap' AND enabled = 1 LIMIT 1`).Scan(&configJSON)
	if err != nil {
		return "", err
	}
	var mapping struct {
		GroupRoles map[string]string `json:"group_roles"`
	}
	if err := json.Unmarshal([]byte(configJSON), &mapping); err != nil {
		return "", err
	}
	for _, group := range groups {
		if role, ok := mapping.GroupRoles[group]; ok {
			return role, nil
		}
	}
	return "", nil
}

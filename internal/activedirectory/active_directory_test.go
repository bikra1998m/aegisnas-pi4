package activedirectory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

type fakeVerifier struct {
	result verifierResult
	err    error
}

func (f fakeVerifier) Verify(context.Context, *config.Config, identityProfile, string) (verifierResult, error) {
	return f.result, f.err
}

func TestPolicyAndAuthenticateWithVerifier(t *testing.T) {
	setupActiveDirectoryDB(t)
	cfg := activeDirectoryTestConfig()
	restore := SetVerifierForTest(fakeVerifier{result: verifierResult{
		Accepted: true,
		Groups:   []string{"AegisNAS-Employees", "Domain Users"},
	}})
	defer restore()

	result, err := Authenticate(context.Background(), cfg, "active-directory", "alice@corp.example.com", "secret-pass")
	require.NoError(t, err)
	require.True(t, result.Accepted)
	assert.Equal(t, "employee", result.Role)
	assert.Equal(t, "portal-active-directory-ldap_bind", result.AuthMethod)
	assert.Equal(t, []string{"AegisNAS-Employees", "Domain Users"}, result.Groups)

	summary, err := db.GetActiveDirectoryEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.AcceptedCount)
	assert.Equal(t, "accepted", summary.LastDecision)
	cache, ok, err := db.GetActiveDirectoryGroupCache("active-directory", "alice@corp.example.com", time.Now().UTC())
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "employee", cache.Role)
}

func TestKerberosCommandVerifierUsesIsolatedCredentialCache(t *testing.T) {
	setupActiveDirectoryDB(t)
	cfg := activeDirectoryTestConfig()
	cfg.ActiveDirectory.AuthMethod = "kerberos"
	cfg.ActiveDirectory.Kerberos.Enabled = true
	cfg.ActiveDirectory.Kerberos.CredentialCacheDir = t.TempDir()
	cfg.ActiveDirectory.LDAPURL = ""
	cfg.ActiveDirectory.BaseDN = ""
	var observedEnv []string
	var observedName string
	var observedArgs []string
	restore := SetCommandRunnerForTest(func(ctx context.Context, env []string, stdin, name string, args ...string) (string, error) {
		if name == "kinit" {
			observedEnv = append([]string(nil), env...)
			observedName = name
			observedArgs = append([]string(nil), args...)
			assert.Equal(t, "secret-pass\n", stdin)
		}
		return "ok", nil
	})
	defer restore()

	result, err := Authenticate(context.Background(), cfg, "active-directory", "alice", "secret-pass")
	require.NoError(t, err)
	assert.True(t, result.Accepted)
	assert.Equal(t, "kinit", observedName)
	assert.Equal(t, []string{"alice@CORP.EXAMPLE.COM"}, observedArgs)
	require.NotEmpty(t, observedEnv)
	assert.Contains(t, observedEnv[0], "KRB5CCNAME=FILE:")
}

func TestBuildReportReflectsBlockedExecutableState(t *testing.T) {
	cfg := activeDirectoryTestConfig()
	cfg.ActiveDirectory.LDAPURL = ""

	report := BuildReport(cfg)

	assert.Equal(t, "blocked", report.Status)
	assert.False(t, report.Summary.SourceExecutable)
	assert.Contains(t, report.Message, "not executable")
}

func activeDirectoryTestConfig() *config.Config {
	return &config.Config{
		Policy: config.PolicyConfig{DefaultRole: "guest-basic"},
		ActiveDirectory: config.ActiveDirectoryConfig{
			Enabled:               true,
			Mode:                  "enforce",
			FailClosed:            true,
			Domain:                "corp.example.com",
			Realm:                 "CORP.EXAMPLE.COM",
			NetBIOSDomain:         "CORP",
			LDAPURL:               "ldaps://dc1.corp.example.com:636",
			BaseDN:                "dc=corp,dc=example,dc=com",
			UserFilter:            "(|(userPrincipalName=%p)(sAMAccountName=%u))",
			GroupFilter:           "(member=%D)",
			AuthMethod:            "ldap_bind",
			DefaultRole:           "guest-basic",
			GroupRoleMappings:     map[string]string{"AegisNAS-Employees": "employee"},
			RequestTimeoutSeconds: 5,
			GroupCacheTTLSeconds:  3600,
			AuditEnabled:          true,
			RetentionLimit:        6000,
			Kerberos: config.ActiveDirectoryKerberosConfig{
				Enabled:      false,
				KinitPath:    "kinit",
				KDestroyPath: "kdestroy",
			},
			Winbind: config.ActiveDirectoryWinbindConfig{
				WbinfoPath:   "wbinfo",
				NTLMAuthPath: "/usr/bin/ntlm_auth",
			},
		},
	}
}

func setupActiveDirectoryDB(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ad.db")
	require.NoError(t, db.Init(path))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(path)
	})
}

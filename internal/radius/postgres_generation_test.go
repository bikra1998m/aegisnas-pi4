package radius

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func postgresModuleURI(t *testing.T, cfg config.DatabaseConfig) *url.URL {
	t.Helper()
	module, err := NewGenerator(&config.Config{Database: cfg}).renderModsPostgreSQL()
	require.NoError(t, err)
	const prefix = `radius_db = "`
	start := strings.Index(module, prefix)
	require.NotEqual(t, -1, start)
	raw := strings.SplitN(module[start+len(prefix):], `"`, 2)[0]
	require.NotContains(t, raw, "${")
	require.NotContains(t, raw, "$ENV{")
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func TestPostgreSQLModulePolicyAndEscaping(t *testing.T) {
	password := `quotes'"\ ${env} $ENV{SECRET} +%&`
	u := &url.URL{Scheme: "postgres", Host: "[::1]:15432", User: url.UserPassword("radius", password), Path: "/aegis nas"}
	q := url.Values{"sslmode": {"disable"}, "sslrootcert": {"/private/root ca.crt"}, "sslcert": {"/private/client.crt"}, "sslkey": {"/private/client.key"}, "options": {"-c TimeZone=Asia/Colombo -c statement_timeout=0"}}
	u.RawQuery = q.Encode()
	actual := postgresModuleURI(t, config.DatabaseConfig{Backend: "postgres", DSN: u.String(), SSLMode: "verify-full", ProductionRequireTLS: true, ConnectTimeoutSeconds: 3, StatementTimeoutMilliseconds: 1234})
	require.Equal(t, "::1", actual.Hostname())
	require.Equal(t, "/aegis nas", actual.Path)
	gotPassword, _ := actual.User.Password()
	require.Equal(t, password, gotPassword)
	require.Equal(t, "verify-full", actual.Query().Get("sslmode"))
	require.Equal(t, "/private/root ca.crt", actual.Query().Get("sslrootcert"))
	require.Equal(t, "/private/client.key", actual.Query().Get("sslkey"))
	require.Equal(t, "3", actual.Query().Get("connect_timeout"))
	require.True(t, strings.HasSuffix(actual.Query().Get("options"), "-c TimeZone=UTC -c statement_timeout=1234"))
	require.NotContains(t, actual.RawQuery, "+")
	require.NotContains(t, actual.Query(), "TimeZone")
	require.NotContains(t, actual.Query(), "statement_timeout")
}

func TestPostgreSQLModuleRejectsAmbiguousOrUnsafeDSN(t *testing.T) {
	for _, suffix := range []string{"?sslmode=disable&sslmode=verify-full", "?sslrootcert=%ZZ", "?options=x;y", "#fragment", "?host=evil", "?unknown=secret", "?sslrootcert=x%0Ay", "?connect_timeout=0", "?statement_timeout=oops"} {
		t.Run(suffix, func(t *testing.T) {
			cfg := &config.Config{Database: config.DatabaseConfig{Backend: "postgres", DSN: "postgres://radius:do-not-print@localhost/db" + suffix}}
			_, err := NewGenerator(cfg).renderModsPostgreSQL()
			require.Error(t, err)
			require.NotContains(t, err.Error(), "do-not-print")
		})
	}
	_, err := NewGenerator(&config.Config{Database: config.DatabaseConfig{Backend: "postgres", DSN: "postgres://r:secret@localhost/db", SSLMode: "disable", ProductionRequireTLS: true}}).renderModsPostgreSQL()
	require.ErrorContains(t, err, "TLS is required")
}

func TestPostgreSQLModuleSecretReference(t *testing.T) {
	t.Setenv("AEGIS_RADIUS_PG_TEST_DSN", "postgres://r:ref-secret@localhost/db?sslmode=disable")
	cfg := &config.Config{Database: config.DatabaseConfig{Backend: "postgres", DSN: "invalid", DSNRef: "env:AEGIS_RADIUS_PG_TEST_DSN"}, Security: config.SecurityConfig{Secrets: config.SecretProviderConfig{Enabled: true, Providers: []string{"env"}, AllowInline: false}}}
	module, err := NewGenerator(cfg).renderModsPostgreSQL()
	require.NoError(t, err)
	require.Contains(t, module, "ref-secret")
	require.Contains(t, module, "sslmode=verify-full")
	require.NotContains(t, module, "AEGIS_RADIUS_PG_TEST_DSN")
	cfg.Database.DSNRef = ""
	_, err = NewGenerator(cfg).renderModsPostgreSQL()
	require.ErrorContains(t, err, "inline secret material")
}

// The opt-in live harness executes this test binary on Linux and consumes the
// actual generated module. It does not substitute a hand-written TLS string.
func TestPostgreSQLModuleLiveFixture(t *testing.T) {
	path := os.Getenv("AEGIS_RADIUS_PG_MODULE_OUTPUT")
	if path == "" {
		t.Skip("isolated FreeRADIUS PostgreSQL fixture not requested")
	}
	cfg := &config.Config{Database: config.DatabaseConfig{Backend: "postgres", DSN: os.Getenv("AEGIS_RADIUS_PG_FIXTURE_DSN"), SSLMode: "verify-full", ProductionRequireTLS: true, ConnectTimeoutSeconds: 3, StatementTimeoutMilliseconds: 1500}}
	module, err := NewGenerator(cfg).renderModsPostgreSQL()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(module), 0600))
}

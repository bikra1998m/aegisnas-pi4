package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestResolverResolvesEnvironmentAndFileRefs(t *testing.T) {
	t.Setenv("AEGIS_TEST_SECRET", "env-secret")
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "radius.secret"), []byte("file-secret\n"), 0600))

	resolver := NewResolver(Options{Enabled: true, Providers: []string{"env", "file"}, FileBaseDir: dir, MaxSecretBytes: 64, AllowInline: true})

	value, err := resolver.Resolve(context.Background(), "env:AEGIS_TEST_SECRET")
	require.NoError(t, err)
	assert.Equal(t, "env-secret", value)

	value, err = resolver.Resolve(context.Background(), "file:radius.secret")
	require.NoError(t, err)
	assert.Equal(t, "file-secret", value)
}

func TestResolverRejectsUnsafeRefs(t *testing.T) {
	resolver := NewResolver(Options{Enabled: true, Providers: []string{"env", "file"}, FileBaseDir: t.TempDir(), MaxSecretBytes: 8, AllowInline: true})

	_, err := resolver.Resolve(context.Background(), "env:$(bad)")
	require.ErrorContains(t, err, "invalid environment")

	_, err = resolver.Resolve(context.Background(), "vault:radius")
	require.ErrorContains(t, err, "unsupported secret provider")

	_, err = resolver.Resolve(context.Background(), "file:../outside.secret")
	require.ErrorContains(t, err, "outside")
}

func TestResolveConfiguredSecretHonorsInlinePolicy(t *testing.T) {
	resolver := NewResolver(Options{Enabled: true, Providers: []string{"env"}, MaxSecretBytes: 64, AllowInline: false})

	_, err := ResolveConfiguredSecret(context.Background(), resolver, "radius.secret", "inline-secret", "")
	require.ErrorContains(t, err, "allow_inline is false")
}

func TestBuildReportRedactsSecretValuesAndBlocksInlineSources(t *testing.T) {
	t.Setenv("AEGIS_RADIUS_SECRET", "super-secret")
	report := BuildReport(context.Background(), &config.Config{
		Security: config.SecurityConfig{Secrets: config.SecretProviderConfig{
			Enabled: true, Providers: []string{"env"}, AllowInline: true, ProductionRequireReferences: true, MaxSecretBytes: 128,
		}},
		Radius: config.RadiusConfig{SecretRef: "env:AEGIS_RADIUS_SECRET"},
		LDAP:   config.LDAPConfig{BindPassword: "directory-secret"},
	}, nil)

	require.Equal(t, "blocked", report.Status)
	assert.Equal(t, 1, report.Summary.ReferenceCount)
	assert.Equal(t, 1, report.Summary.InlineCount)
	assert.NotContains(t, report.Sources[0].Message, "super-secret")
	for _, source := range report.Sources {
		assert.NotContains(t, source.Message, "directory-secret")
	}
}

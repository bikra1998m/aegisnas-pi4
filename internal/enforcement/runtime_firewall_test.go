package enforcement

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestBuildRuntimeFirewallRuleset(t *testing.T) {
	ruleset := buildRuntimeFirewallRuleset([]string{"192.0.2.10", "192.0.2.11"})

	assert.Contains(t, ruleset, "table inet aegis_runtime")
	assert.Contains(t, ruleset, "elements = { 192.0.2.10, 192.0.2.11 }")
	assert.Contains(t, ruleset, "ip saddr @quarantine_ipv4 drop")
	assert.NotContains(t, ruleset, "delete table inet aegis_runtime")
}

func TestCanIgnoreRuntimeFirewallDeleteError(t *testing.T) {
	assert.True(t, canIgnoreRuntimeFirewallDeleteError("Error: No such file or directory"))
	assert.False(t, canIgnoreRuntimeFirewallDeleteError("Error: Operation not permitted"))
}

func TestResetRuntimeFirewallTableIgnoresMissingTable(t *testing.T) {
	original := runtimeFirewallExecCommand
	runtimeFirewallExecCommand = fakeRuntimeFirewallCommand(t, "delete-missing")
	defer func() { runtimeFirewallExecCommand = original }()

	assert.NoError(t, resetRuntimeFirewallTable())
}

func TestApplyRuntimeFirewallRulesetReturnsErrors(t *testing.T) {
	original := runtimeFirewallExecCommand
	runtimeFirewallExecCommand = fakeRuntimeFirewallCommand(t, "apply-fails")
	defer func() { runtimeFirewallExecCommand = original }()

	err := applyRuntimeFirewallRuleset(buildRuntimeFirewallRuleset(nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "apply runtime firewall")
	assert.Contains(t, err.Error(), "syntax error")
}

func TestSyncRuntimeFirewallRebuildsTableAfterMissingDelete(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "runtime-firewall.db")
	require.NoError(t, db.Init(dbFile))
	defer db.Close()
	require.NoError(t, db.Migrate())

	_, err := db.DB.Exec(`INSERT INTO sessions (id, username, ip, role, start_time) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		"s1", "guest1", "192.0.2.44", "quarantine-guest")
	require.NoError(t, err)

	stdinFile := filepath.Join(t.TempDir(), "runtime-firewall.nft")
	t.Setenv("RUNTIME_FIREWALL_STDIN_FILE", stdinFile)

	originalExec := runtimeFirewallExecCommand
	originalDB := db.DB
	runtimeFirewallExecCommand = fakeRuntimeFirewallCommand(t, "delete-missing-apply-ok")
	defer func() {
		runtimeFirewallExecCommand = originalExec
		db.DB = originalDB
	}()

	require.NoError(t, SyncRuntimeFirewall())

	content, err := os.ReadFile(stdinFile)
	require.NoError(t, err)
	rendered := string(content)
	assert.Contains(t, rendered, "192.0.2.44")
	assert.NotContains(t, rendered, "delete table inet aegis_runtime")
}

func fakeRuntimeFirewallCommand(t *testing.T, mode string) func(string, ...string) *exec.Cmd {
	t.Helper()

	return func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestRuntimeFirewallCommandHelper", "--", mode, command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = append(os.Environ(), "GO_WANT_RUNTIME_FIREWALL_HELPER=1")
		return cmd
	}
}

func TestRuntimeFirewallCommandHelper(t *testing.T) {
	if os.Getenv("GO_WANT_RUNTIME_FIREWALL_HELPER") != "1" {
		return
	}

	args := os.Args
	separator := 0
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator == 0 || len(args) <= separator+2 {
		fmt.Fprint(os.Stderr, "missing helper args")
		os.Exit(2)
	}

	mode := args[separator+1]
	commandArgs := args[separator+2:]
	isDelete := len(commandArgs) >= 5 && commandArgs[0] == "nft" && commandArgs[1] == "delete"
	isApply := len(commandArgs) >= 3 && commandArgs[0] == "nft" && commandArgs[1] == "-f"

	switch mode {
	case "delete-missing":
		if isDelete {
			fmt.Fprint(os.Stderr, "Error: No such file or directory")
			os.Exit(1)
		}
	case "apply-fails":
		if isApply {
			fmt.Fprint(os.Stderr, "syntax error")
			os.Exit(1)
		}
	case "delete-missing-apply-ok":
		if isDelete {
			fmt.Fprint(os.Stderr, "Error: No such file or directory")
			os.Exit(1)
		}
		if isApply {
			content, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "read stdin: %v", err)
				os.Exit(1)
			}
			if target := os.Getenv("RUNTIME_FIREWALL_STDIN_FILE"); strings.TrimSpace(target) != "" {
				if err := os.WriteFile(target, content, 0o600); err != nil {
					fmt.Fprintf(os.Stderr, "write stdin file: %v", err)
					os.Exit(1)
				}
			}
		}
	}

	os.Exit(0)
}

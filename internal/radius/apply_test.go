package radius

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRestartSystemdServiceTreatsRecoveredRestartAsSuccess(t *testing.T) {
	restore := stubSystemdRunner(t, func(name string, args ...string) ([]byte, error) {
		if name != "systemctl" {
			t.Fatalf("unexpected command %q", name)
		}
		switch strings.Join(args, " ") {
		case "restart freeradius":
			return []byte("watchdog ping missed"), errors.New("exit status 1")
		case "is-active freeradius":
			return []byte("active\n"), nil
		default:
			t.Fatalf("unexpected systemctl args %q", strings.Join(args, " "))
		}
		return nil, nil
	})
	defer restore()

	if err := restartSystemdService("freeradius", time.Second); err != nil {
		t.Fatalf("expected recovered restart to succeed: %v", err)
	}
}

func TestRestartSystemdServiceReturnsActivationFailure(t *testing.T) {
	restore := stubSystemdRunner(t, func(name string, args ...string) ([]byte, error) {
		if name != "systemctl" {
			t.Fatalf("unexpected command %q", name)
		}
		switch strings.Join(args, " ") {
		case "restart freeradius":
			return []byte("restart failed"), errors.New("exit status 1")
		case "is-active freeradius":
			return []byte("failed\n"), errors.New("exit status 3")
		default:
			t.Fatalf("unexpected systemctl args %q", strings.Join(args, " "))
		}
		return nil, nil
	})
	defer restore()

	err := restartSystemdService("freeradius", 0)
	if err == nil {
		t.Fatal("expected unrecovered restart to fail")
	}
	if !strings.Contains(err.Error(), "restart freeradius failed") {
		t.Fatalf("expected restart context in error, got %v", err)
	}
	if !strings.Contains(err.Error(), "last state \"failed\"") {
		t.Fatalf("expected activation state in error, got %v", err)
	}
}

func stubSystemdRunner(t *testing.T, runner func(string, ...string) ([]byte, error)) func() {
	t.Helper()
	oldRunner := runSystemCommand
	oldInterval := systemdPollInterval
	runSystemCommand = runner
	systemdPollInterval = 0
	return func() {
		runSystemCommand = oldRunner
		systemdPollInterval = oldInterval
	}
}

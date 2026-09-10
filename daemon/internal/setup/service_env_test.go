package setup

import (
	"strings"
	"testing"
)

// The daemon reads AKASHA_MAX_SESSION_TTL (the session-TTL ceiling) and
// AKASHA_AUDIT_MAX_SIZE / _KEEP (audit retention) from its environment at
// RUNTIME. launchd and systemd start the service with a clean environment, so
// until these were written into the service file, setting one affected only a
// hand-started `akasha start` and silently not the login-service daemon — the
// gap D5 flagged for the TTL ceiling specifically. All three share it, so all
// three are propagated.
func TestDaemonServiceEnvPropagatesTheDaemonKnobs(t *testing.T) {
	t.Setenv("AKASHA_MAX_SESSION_TTL", "8h")
	t.Setenv("AKASHA_AUDIT_MAX_SIZE", "10485760")
	t.Setenv("AKASHA_AUDIT_KEEP", "20")
	// A variable the daemon does NOT read at runtime must not leak into the
	// service file; only the documented machine knobs travel.
	t.Setenv("AKASHA_AGENT_KEY", "should-not-appear")

	env := daemonServiceEnv()
	for _, k := range []string{"AKASHA_MAX_SESSION_TTL", "AKASHA_AUDIT_MAX_SIZE", "AKASHA_AUDIT_KEEP"} {
		if _, ok := env[k]; !ok {
			t.Errorf("%s was set but not carried into the service environment", k)
		}
	}
	if _, ok := env["AKASHA_AGENT_KEY"]; ok {
		t.Error("AKASHA_AGENT_KEY leaked into the service environment — only runtime daemon knobs belong there")
	}
}

// An operator who sets nothing gets the same service file as before: no empty
// EnvironmentVariables dict, no stray Environment= lines.
func TestServiceEnvIsAbsentWhenNothingIsSet(t *testing.T) {
	t.Setenv("AKASHA_MAX_SESSION_TTL", "")
	t.Setenv("AKASHA_AUDIT_MAX_SIZE", "")
	t.Setenv("AKASHA_AUDIT_KEEP", "")
	if env := daemonServiceEnv(); len(env) != 0 {
		t.Fatalf("expected no service env, got %v", env)
	}
	if b := launchdEnvBlock(nil); b != "" {
		t.Errorf("empty env must produce no plist block, got %q", b)
	}
	if l := systemdEnvLines(nil); l != "" {
		t.Errorf("empty env must produce no unit lines, got %q", l)
	}

	plist := renderLaunchdPlist("/bin/akasha", "/d/v.db", "/d/a.log", "/d/a.sock", nil)
	if strings.Contains(plist, "EnvironmentVariables") {
		t.Error("a default plist should carry no EnvironmentVariables dict")
	}
	unit := renderSystemdUnit("/bin/akasha", "/d/v.db", "/d/a.log", "/d/a.sock", nil)
	if strings.Contains(unit, "Environment=") {
		t.Error("a default unit should carry no Environment= line")
	}
}

// The set ceiling actually lands in the rendered plist and unit, in a form the
// service manager reads — the whole point, since a value the daemon cannot see
// is the bug.
func TestRenderedServiceFilesCarryTheCeiling(t *testing.T) {
	env := map[string]string{"AKASHA_MAX_SESSION_TTL": "8h", "AKASHA_AUDIT_KEEP": "20"}

	plist := renderLaunchdPlist("/bin/akasha", "/d/v.db", "/d/a.log", "/d/a.sock", env)
	if !strings.Contains(plist, "<key>EnvironmentVariables</key>") {
		t.Fatalf("plist has no EnvironmentVariables dict:\n%s", plist)
	}
	if !strings.Contains(plist, "<key>AKASHA_MAX_SESSION_TTL</key><string>8h</string>") {
		t.Errorf("plist does not carry the ceiling:\n%s", plist)
	}
	// The dict sits inside the top-level <dict>, before RunAtLoad — a stray
	// block after </plist> or inside ProgramArguments would not be read.
	if strings.Index(plist, "EnvironmentVariables") > strings.Index(plist, "<key>RunAtLoad</key>") {
		t.Error("the EnvironmentVariables dict is placed after RunAtLoad, not with the other top-level keys")
	}

	unit := renderSystemdUnit("/bin/akasha", "/d/v.db", "/d/a.log", "/d/a.sock", env)
	if !strings.Contains(unit, `Environment="AKASHA_MAX_SESSION_TTL=8h"`) {
		t.Errorf("unit does not carry the ceiling:\n%s", unit)
	}
	// It must be in the [Service] section, before [Install].
	if strings.Index(unit, "Environment=") > strings.Index(unit, "[Install]") {
		t.Error("Environment= lines are after [Install], where systemd will not apply them to the service")
	}
}

// Deterministic output: the same environment must render byte-identical files
// across runs, or every `akasha setup` rewrites the service file and churns it.
func TestServiceEnvRenderingIsDeterministic(t *testing.T) {
	env := map[string]string{"AKASHA_AUDIT_KEEP": "20", "AKASHA_MAX_SESSION_TTL": "8h", "AKASHA_AUDIT_MAX_SIZE": "1048576"}
	first := launchdEnvBlock(env)
	for i := 0; i < 20; i++ {
		if launchdEnvBlock(env) != first {
			t.Fatal("launchdEnvBlock is not deterministic across calls — map order leaked into the file")
		}
	}
	// Sorted: AUDIT_KEEP < AUDIT_MAX_SIZE < MAX_SESSION_TTL.
	ai := strings.Index(first, "AKASHA_AUDIT_KEEP")
	bi := strings.Index(first, "AKASHA_MAX_SESSION_TTL")
	if ai < 0 || bi < 0 || ai > bi {
		t.Errorf("keys are not in sorted order:\n%s", first)
	}
}

// A value carrying an XML metacharacter is escaped, so a hand-set ceiling can
// never break the plist it lands in.
func TestLaunchdEnvBlockEscapesValues(t *testing.T) {
	block := launchdEnvBlock(map[string]string{"AKASHA_MAX_SESSION_TTL": `8h<&"`})
	if strings.Contains(block, "8h<&") {
		t.Errorf("the value was not XML-escaped, so the plist is malformed:\n%s", block)
	}
	if !strings.Contains(block, "&lt;") || !strings.Contains(block, "&amp;") {
		t.Errorf("expected escaped entities in:\n%s", block)
	}
}

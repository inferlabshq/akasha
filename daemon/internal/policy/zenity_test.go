package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubZenity points zenityPaths at a shell script standing in for zenity, and
// records the argv it was called with. Returns the path of the argv log.
func stubZenity(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	argv := filepath.Join(dir, "argv")
	bin := filepath.Join(dir, "zenity")
	// Record-separated, and with the count first: an argv element may itself
	// contain newlines (the dialog body does), so a newline-delimited log could
	// not tell one multi-line argument from several.
	script := "#!/bin/sh\n{ printf '%s\\036' \"$#\"; for a in \"$@\"; do printf '%s\\036' \"$a\"; done; } > " + argv + "\n" + body + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := zenityPaths
	zenityPaths = []string{bin}
	t.Cleanup(func() { zenityPaths = old })
	t.Setenv("DISPLAY", ":0")
	return argv
}

// Only zenity's exit 0 — the Allow button — may proceed. 1 is Deny OR Escape,
// 5 is the dialog's own timeout, 2 is a zenity error; every one of those is a
// human who did not say yes, or no human at all.
func TestZenityAllowsOnlyOnExitZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit string
		want bool
	}{
		{"allow button", "exit 0", true},
		{"deny or escape", "exit 1", false},
		{"dialog timed out", "exit 5", false},
		{"zenity error", "exit 2", false},
		{"unknown option on an old zenity", "exit 255", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubZenity(t, tc.exit)
			got := (&linuxDialogApprover{}).Approve(Request{Action: "retrieve"}, time.Second)
			if got != tc.want {
				t.Fatalf("Approve() = %v, want %v", got, tc.want)
			}
		})
	}
}

// A dialog nobody ever answers must not hold a gated operation open forever.
// zenity's own --timeout normally ends it; the grace kill is what covers a
// zenity that ignores it or wedges.
func TestZenityHangIsKilledAndDenied(t *testing.T) {
	stubZenity(t, "sleep 30")
	old := dialogKillGrace
	dialogKillGrace = 200 * time.Millisecond
	t.Cleanup(func() { dialogKillGrace = old })

	start := time.Now()
	if (&linuxDialogApprover{}).Approve(Request{Action: "retrieve"}, 100*time.Millisecond) {
		t.Fatal("a hung dialog must deny")
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("waited %v for a hung dialog — the grace kill did not fire", el)
	}
}

// The dialog's security properties live in its argv. Losing --default-cancel
// makes Enter mean Allow; losing --no-markup hands the caller Pango.
func TestZenityArgsPreserveDefaultDeny(t *testing.T) {
	argv := stubZenity(t, "exit 1")
	(&linuxDialogApprover{}).Approve(Request{Action: "retrieve", Token: "prod-key"}, 42*time.Second)

	argc, args := readArgv(t, argv)
	for _, want := range []string{"--question", "--no-markup", "--default-cancel", "--timeout=42", "--ok-label=Allow", "--cancel-label=Deny"} {
		found := false
		for _, a := range args {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %s in argv %q", want, args)
		}
	}
	// The multi-line body must arrive as ONE argv element. That is the whole
	// reason this side has no quoting layer to get wrong, unlike the generated
	// AppleScript on macOS.
	if argc != len(args) {
		t.Fatalf("argc %d but %d elements logged", argc, len(args))
	}
	body := ""
	for _, a := range args {
		if strings.HasPrefix(a, "--text=") {
			if body != "" {
				t.Fatal("the dialog body was split across argv elements")
			}
			body = a
		}
	}
	if !strings.Contains(body, "Secret: prod-key") {
		t.Errorf("--text did not carry the request: %q", body)
	}
	if !strings.Contains(body, "Operation: retrieve") {
		t.Errorf("--text lost the operation line: %q", body)
	}
}

// readArgv parses the record-separated log written by stubZenity.
func readArgv(t *testing.T, path string) (argc int, args []string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(raw), "\x1e")
	if n := len(parts); n > 0 && parts[n-1] == "" {
		parts = parts[:n-1] // trailing separator
	}
	if len(parts) == 0 {
		t.Fatal("stub zenity logged nothing")
	}
	if _, err := fmt.Sscanf(parts[0], "%d", &argc); err != nil {
		t.Fatalf("argc %q: %v", parts[0], err)
	}
	return argc, parts[1:]
}

// zenity treats --timeout=0 as "no timeout", so a policy with a sub-second
// ask_timeout would leave the dialog up until the grace kill.
func TestZenityTimeoutNeverZero(t *testing.T) {
	argv := stubZenity(t, "exit 1")
	(&linuxDialogApprover{}).Approve(Request{Action: "retrieve"}, 0)
	_, args := readArgv(t, argv)
	if slicesContains(args, "--timeout=0") {
		t.Error("--timeout=0 means NO timeout to zenity")
	}
}

// A caller-supplied value must not be able to style or hide itself. Pango
// markup is the Linux equivalent of the AppleScript line-break forgery.
func TestZenityTextStripsMarkup(t *testing.T) {
	got := zenityText(Request{
		Action: "retrieve",
		Task:   `<span size="0">hidden</span> and <b>Operation: broker aws:dev</b>`,
	})
	if strings.ContainsAny(got, "<>") {
		t.Fatalf("markup characters survived: %q", got)
	}
	// Neutralise layout, do not censor content — same contract as dialogSafe.
	if !strings.Contains(got, "hidden") {
		t.Errorf("text content was dropped: %q", got)
	}
}

// The dialog is what decides whether a gated operation proceeds, so it must
// never be chosen from PATH.
func TestZenityIsNotResolvedFromPATH(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "zenity"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("DISPLAY", ":0")
	old := zenityPaths
	zenityPaths = []string{filepath.Join(dir, "does-not-exist")}
	t.Cleanup(func() { zenityPaths = old })

	if (&linuxDialogApprover{}).Approve(Request{Action: "retrieve"}, time.Second) {
		t.Fatal("a zenity found on PATH was allowed to answer the prompt")
	}
}

// "I cannot ask" is not "they said no". The reason has to name the fix.
func TestLinuxApproverReportsWhyItCannotAsk(t *testing.T) {
	l := &linuxDialogApprover{}

	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	if why := l.Unavailable(); !strings.Contains(why, "graphical session") {
		t.Errorf("headless reason = %q", why)
	}

	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	old := zenityPaths
	zenityPaths = []string{filepath.Join(t.TempDir(), "nope")}
	t.Cleanup(func() { zenityPaths = old })
	if why := l.Unavailable(); !strings.Contains(why, "zenity") {
		t.Errorf("missing-zenity reason = %q", why)
	}

	stubZenity(t, "exit 1")
	if why := l.Unavailable(); why != "" {
		t.Errorf("a usable dialog reported unavailable: %q", why)
	}
}

// Authorize must surface the unavailability rather than the generic refusal —
// otherwise a missing zenity looks exactly like a human clicking Deny.
func TestAuthorizeReportsUnavailableApprover(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("rules:\n  - {effect: ask}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(path)
	e.SetApprover(&linuxDialogApprover{})
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	err := e.Authorize(Request{Action: "retrieve"})
	if err == nil {
		t.Fatal("an unreachable approver must deny")
	}
	if !strings.Contains(err.Error(), "graphical session") {
		t.Errorf("denial did not say why approval was impossible: %v", err)
	}
}

func slicesContains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

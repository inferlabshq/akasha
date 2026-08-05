package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// memStore is an in-memory StateStore.
type memStore struct{ digest string }

func (m *memStore) PolicyState() (string, error)  { return m.digest, nil }
func (m *memStore) SetPolicyState(d string) error { m.digest = d; return nil }

const denyAll = "default: deny\nrules: []\n"

// TestFirstRunNoPolicyStillAllows: the engine is opt-in and must stay opt-in.
// A machine that has never had a policy file allows everything — breaking that
// would deny every operation on a fresh install.
func TestFirstRunNoPolicyStillAllows(t *testing.T) {
	e := NewEngine(filepath.Join(t.TempDir(), "policy.yaml"))
	e.SetStateStore(&memStore{})
	if err := e.Authorize(Request{Action: "retrieve"}); err != nil {
		t.Fatalf("first run with no policy must allow: %v", err)
	}
}

// TestDeletedPolicyFailsClosedWhenPreviouslyInstalled: `rm policy.yaml` used to
// be a silent kill switch — the next request was allow-all, with no log line.
func TestDeletedPolicyFailsClosedWhenPreviouslyInstalled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(denyAll), 0600); err != nil {
		t.Fatal(err)
	}
	store := &memStore{}
	var events []string
	e := NewEngine(path)
	e.SetStateStore(store)
	e.SetNotifier(func(action, _ string) { events = append(events, action) })

	if err := e.Authorize(Request{Action: "retrieve"}); err == nil {
		t.Fatal("default: deny should have denied")
	}
	if store.digest == "" {
		t.Fatal("a successful load must record that a policy is installed")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	err := e.Authorize(Request{Action: "retrieve"})
	if err == nil {
		t.Fatal("BYPASS: deleting policy.yaml re-allowed everything")
	}
	if !strings.Contains(err.Error(), "policy disable") {
		t.Errorf("error should point at the deliberate off-switch, got: %v", err)
	}
	if !contains(events, EventMissing) {
		t.Errorf("deletion must be audited, got events %v", events)
	}
}

// Clearing the recorded state is the deliberate off-switch (`akasha policy
// disable`), and it must actually restore allow-all.
func TestDisableRestoresOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(denyAll), 0600); err != nil {
		t.Fatal(err)
	}
	store := &memStore{}
	e := NewEngine(path)
	e.SetStateStore(store)
	_ = e.Authorize(Request{Action: "retrieve"})

	os.Remove(path)
	if err := e.Authorize(Request{Action: "retrieve"}); err == nil {
		t.Fatal("expected fail-closed before disable")
	}
	store.digest = "" // what ClearPolicyState does
	if err := e.Authorize(Request{Action: "retrieve"}); err != nil {
		t.Fatalf("after disable, a missing policy must allow again: %v", err)
	}
}

// TestPolicyCacheDetectsSameSizeSameMtimeEdit: the cache was keyed on a stat
// taken BEFORE the read, so an attacker could load a permissive policy, restore
// the original padded to the same length, copy the mtime back, and leave the
// daemon enforcing their copy while `cat` showed the real one.
func TestPolicyCacheDetectsSameSizeSameMtimeEdit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	permissive := "default: allow\nrules: []\n#pad"
	restrictive := "default: deny\nrules: []\n#padd"
	if len(permissive) != len(restrictive) {
		t.Fatalf("test setup: contents must be the same length (%d vs %d)", len(permissive), len(restrictive))
	}

	if err := os.WriteFile(path, []byte(permissive), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	when := st.ModTime()

	e := NewEngine(path)
	if err := e.Authorize(Request{Action: "retrieve"}); err != nil {
		t.Fatalf("permissive policy should allow: %v", err)
	}

	// Same size, same mtime, different content.
	if err := os.WriteFile(path, []byte(restrictive), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
	if err := e.Authorize(Request{Action: "retrieve"}); err == nil {
		t.Fatal("stale cache: the engine kept enforcing the previous content")
	}
}

// A file that exists but does not parse still denies everything, loudly — and
// must NOT arm the installed-tripwire, or a syntax error would wedge the daemon
// into deny-all even after the file is removed.
func TestInvalidPolicyDeniesButDoesNotArmTripwire(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("rules: [{effect: maybe}]"), 0600); err != nil {
		t.Fatal(err)
	}
	store := &memStore{}
	e := NewEngine(path)
	e.SetStateStore(store)

	if err := e.Authorize(Request{Action: "retrieve"}); err == nil {
		t.Fatal("an unparseable policy must deny")
	}
	if store.digest != "" {
		t.Fatal("an unparseable policy must not record itself as installed")
	}
	os.Remove(path)
	if err := e.Authorize(Request{Action: "retrieve"}); err != nil {
		t.Fatalf("removing a never-valid policy should return to allow-all: %v", err)
	}
}

// Without a state store the engine keeps its original behaviour, so embedding
// it somewhere with no vault does not suddenly deny everything.
func TestNoStateStoreKeepsLegacyBehaviour(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(path, []byte(denyAll), 0600)
	e := NewEngine(path)
	_ = e.Authorize(Request{Action: "retrieve"})
	os.Remove(path)
	if err := e.Authorize(Request{Action: "retrieve"}); err != nil {
		t.Fatalf("no store: missing file must allow, got %v", err)
	}
}

// Editing a live policy is audited as a change, not a fresh load.
func TestPolicyEditEmitsChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(path, []byte("default: allow\nrules: []\n"), 0600)
	var events []string
	e := NewEngine(path)
	e.SetStateStore(&memStore{})
	e.SetNotifier(func(action, _ string) { events = append(events, action) })

	_ = e.Authorize(Request{Action: "retrieve"})
	time.Sleep(5 * time.Millisecond)
	os.WriteFile(path, []byte(denyAll), 0600)
	_ = e.Authorize(Request{Action: "retrieve"})

	if !contains(events, EventLoaded) || !contains(events, EventChanged) {
		t.Fatalf("want a load then a change, got %v", events)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

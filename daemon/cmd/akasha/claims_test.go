package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inferlabshq/akasha/daemon/internal/vault"
)

// These pin one rule across four commands: a command may not report a state it
// did not check.
//
// It was the single largest defect class in this codebase — nine of the
// thirty-three critical/high findings from the pre-launch sweep, and every bug
// found in the macOS pass afterwards. The instances differ; the habit is one.

// `status` is documented as the health check and answered {"status":"ok"} while
// nothing could be brokered, because it reported only the numbers it happened
// to hold. Six of seven reviewers were misled by that answer at least once.
func TestStatusNamesTheSubsystemsThatAreBroken(t *testing.T) {
	for _, tc := range []struct {
		name, health string
		want         []string
		absent       []string
	}{
		{
			name:   "no templates loaded",
			health: `{"status":"ok","vault_total":2,"templates_loaded":0,"policy":"ok"}`,
			want:   []string{"NO PROVIDER TEMPLATES", "template list"},
		},
		{
			name:   "policy will not parse",
			health: `{"status":"ok","vault_total":2,"templates_loaded":6,"policy":"invalid: line 4: bad"}`,
			want:   []string{"POLICY FILE DOES NOT PARSE", "line 4: bad"},
		},
		{
			name:   "healthy says nothing extra",
			health: `{"status":"ok","vault_total":2,"templates_loaded":6,"policy":"ok"}`,
			absent: []string{"⚠"},
		},
		{
			name:   "an unidentified caller gets no counts and no false alarm",
			health: `{"status":"ok"}`,
			absent: []string{"NO PROVIDER TEMPLATES"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			reportBrokenSubsystems(&buf, tc.health)
			got := buf.String()
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("status should mention %q, got:\n%s", w, got)
				}
			}
			for _, a := range tc.absent {
				if strings.Contains(got, a) {
					t.Errorf("status should not mention %q, got:\n%s", a, got)
				}
			}
		})
	}
}

// `--assume` checked the PROVIDER and never the label, so a profile that does
// not exist was accepted and the run banner announced it as brokerable.
func TestAssumeRefusesALabelTheVaultDoesNotHold(t *testing.T) {
	seen := recordingLabels(t, []string{"github:default", "aws:default"})
	defer seen()

	if err := assertAssumable([]string{"github:default"}); err != nil {
		t.Errorf("a label the vault holds must be accepted: %v", err)
	}

	err := assertAssumable([]string{"github:this-profile-does-not-exist"})
	if err == nil {
		t.Fatal("a label the vault does not hold was accepted")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no credential named") {
		t.Errorf("the error should say the credential is absent, got: %v", err)
	}
	// Naming what DOES exist is the difference between a refusal and a dead end.
	if !strings.Contains(msg, "github:default") {
		t.Errorf("the error should list what the vault has, got: %v", err)
	}
}

// Unverifiable is not the same as absent. With no daemon to ask, the check must
// step aside rather than invent a refusal — otherwise it becomes the same bug
// pointed the other way.
func TestAssumeSkipsTheCheckWhenItCannotAsk(t *testing.T) {
	// A socket that ACCEPTS and then hangs up, rather than a path that does not
	// exist.
	//
	// Pointing at a missing path does not isolate anything: when the socket
	// cannot be dialled the client falls back to the shared HTTP port, and that
	// fallback is gated on cobra flags which a unit test never sets. So an
	// earlier version of this test reached the DEVELOPER'S OWN daemon and
	// listed their real vault — and passed only on a machine where no daemon
	// happened to be running.
	//
	// A live listener that answers nothing keeps the dial succeeding, so no
	// fallback fires, and the request fails for the reason under test.
	dir, err := os.MkdirTemp("/tmp", "akdead")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "d.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close() // hang up without answering
		}
	}()

	old := socketPath
	socketPath = ln.Addr().String()
	defer func() { socketPath = old }()

	if err := assertAssumable([]string{"anything:at-all"}); err != nil {
		t.Errorf("a daemon that cannot answer must not become 'no such credential': %v", err)
	}
}

// `status` reported on policy, TTLs and the audit log while saying nothing
// about the fact that none of them are in the path a default vault is read by.
//
// The vault key is the OS keychain entry plus a PLAINTEXT row in vault.db, so
// without a passphrase any process running as the user decrypts the whole vault
// offline — no socket, no policy evaluation, no audit record (measured in
// internal/vault/offline_decrypt_test.go). A health check that lists the
// controls and omits the ceiling above them is reporting a state it did not
// check, which is the habit this file exists to break.
func TestStatusSaysWhatProtectsTheVaultKey(t *testing.T) {
	newVault := func(t *testing.T, opts vault.Options) string {
		t.Helper()
		// Never the developer's own vault: a temp path, and a package that
		// isolates its keychain entries under test.
		path := filepath.Join(t.TempDir(), "vault.db")
		opts.AllowNewVaultKey = true
		v, err := vault.Open(path, opts)
		if err != nil {
			t.Fatalf("vault.Open: %v", err)
		}
		v.Close()
		return path
	}

	t.Run("no passphrase", func(t *testing.T) {
		var buf bytes.Buffer
		reportVaultKey(&buf, newVault(t, vault.Options{}))
		got := buf.String()
		for _, want := range []string{
			"no passphrase",       // the state
			"without the daemon",  // why the rest of status does not cover it
			"no policy check",     // named, so it cannot be read as theoretical
			"akasha run",          // a route that works today
			"docs/THREATMODEL.md", // where the full statement lives
		} {
			if !strings.Contains(got, want) {
				t.Errorf("status should mention %q, got:\n%s", want, got)
			}
		}
	})

	// The user who took the trade must not be told they did not. A standing
	// warning that is wrong for the people who acted on it is how the next one
	// gets ignored.
	t.Run("passphrase set", func(t *testing.T) {
		var buf bytes.Buffer
		reportVaultKey(&buf, newVault(t, vault.Options{Passphrase: []byte("a second factor")}))
		if got := buf.String(); got != "" {
			t.Errorf("a passphrase-protected vault must not be told it has no passphrase:\n%s", got)
		}
	})

	// No vault is not a claim about vaults. `status` runs against a --db that
	// may not exist yet, and inventing an answer there is the same defect.
	t.Run("no vault at that path", func(t *testing.T) {
		var buf bytes.Buffer
		reportVaultKey(&buf, filepath.Join(t.TempDir(), "absent.db"))
		if got := buf.String(); got != "" {
			t.Errorf("status described the key of a vault that does not exist:\n%s", got)
		}
	})
}

package sandbox

import (
	"os"
	"path/filepath"
)

// Surface builds the deny set for an akasha data directory, plus the doors a
// sandboxed agent legitimately needs.
//
// dataDir is ~/.akasha; runDir is the per-run temp directory holding the
// generated broker config and the run's socket. The socket lives in runDir
// rather than dataDir on purpose: that lets the whole data directory be denied
// with no hole punched in it.
func Surface(dataDir, runDir string, extraRead, extraWrite []string) Spec {
	home := homeDir()
	s := Spec{
		DenyKeychain:      true,
		DenyPeerProcesses: true,
		DenyDeputies:      true,
	}

	deny := func(path string, tree bool, why string) {
		if path == "" {
			return
		}
		s.Deny = append(s.Deny, Rule{Path: filepath.Clean(path), Tree: tree, Mode: DenyAll, Why: why})
	}

	// The akasha data directory is a deny-default ISLAND. Polarity inverts
	// inside it, so a rotated audit segment, a WAL sidecar, or a file a future
	// version adds is denied BY CONSTRUCTION rather than by enumeration. This
	// is also what removes any need to pattern-match filenames, which is what
	// keeps regex out of the generated profile.
	deny(dataDir, true, "akasha data directory: vault, audit log, sessions, approvals, policy")

	// …with the provider templates allowed back, because the broker inside the
	// sandbox needs them and they are not secret.
	//
	// Denying the whole data directory took the templates with it, and every
	// brokered call inside a run then failed with `no template for provider
	// "github"` — `akasha exec --assume` and the git credential helper alike.
	// The sandbox would launch and then broker nothing, which is worse than
	// refusing to launch: the agent falls back to whatever plaintext it can
	// find and the run looks like it worked.
	//
	// Safe to allow: a template is declarative data and is itself the audit
	// list of what a provider reads — `akasha template explain` prints it. The
	// secrets in this directory are vault.db, the audit log, cli.key and the
	// session dirs, none of which are these. Read-only, so a sandboxed agent
	// still cannot add a provider or edit what one reads.
	for _, d := range []string{
		filepath.Join(dataDir, "templates.dist"), // shipped bundle
		filepath.Join(dataDir, "templates"),      // the user's own
	} {
		s.AllowReadTry = append(s.AllowReadTry, d)
	}

	// Key material and materialized credentials outside the data dir.
	if home != "" {
		deny(filepath.Join(home, "akasha-backup.akb"), false, "vault key backup")
		deny(filepath.Join(home, "akasha-key.backup"), false, "vault key backup (legacy name)")
	}
	deny("/Volumes/akasha-sessions", true, "macOS RAM disk holding materialized session credentials")
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		deny(filepath.Join(x, "akasha"), true, "session credentials (tmpfs)")
	}
	deny(filepath.Join("/dev/shm", "akasha-"+itoa(os.Getuid())), true, "session credentials (tmpfs)")

	// Well-known plaintext credentials. ~/.ssh is a deny-default island too:
	// deny the tree and allow back the non-secret files, so a private key added
	// AFTER launch is denied by construction — enumerating id_* at launch would
	// race it.
	if home != "" {
		for _, rel := range []string{".aws", ".ssh", ".config/gcloud", ".config/gh", ".gnupg", ".docker"} {
			deny(filepath.Join(home, rel), true, "plaintext credentials")
		}
		for _, rel := range []string{".netrc", ".git-credentials", ".pgpass"} {
			deny(filepath.Join(home, rel), false, "plaintext credentials")
		}
		deny(filepath.Join(home, "Library/Keychains"), true, "macOS keychain files")
	}
	deny("/Library/Keychains", true, "macOS system keychain files")

	// ── Doors ───────────────────────────────────────────────────────────────
	// The run directory as ONE subpath rule.
	//
	// INVARIANT: never enumerate the files inside it. The broker config
	// rendered there takes its filename from a provider template, and this
	// package turns paths into a generated program on macOS. Allowing the
	// directory keeps every template-supplied value out of that program. The
	// obvious future "optimisation" — allow each rendered file individually —
	// would route a template value into generated code, which is precisely the
	// surface the plugin format was designed to avoid.
	if runDir != "" {
		s.AllowWrite = append(s.AllowWrite, filepath.Clean(runDir))
	}

	// git identity: the generated gitconfig re-includes the user's real one,
	// and ~/.gitconfig is not a credential.
	if home != "" {
		// AllowReadTry, not AllowRead: all three belong to the user, and a
		// machine where none of them has ever been created is normal. See the
		// field comment in sandbox.go for why tolerating their absence cannot
		// widen the sandbox.
		s.AllowReadTry = append(s.AllowReadTry,
			filepath.Join(home, ".gitconfig"),
		)
		// ssh: the private key never becomes readable. ssh-agent brokers it
		// over SSH_AUTH_SOCK, which allow-by-default already permits — the same
		// architecture akasha uses, where the secret stays with the broker.
		for _, rel := range []string{".ssh/config", ".ssh/known_hosts"} {
			s.AllowReadTry = append(s.AllowReadTry, filepath.Join(home, rel))
		}
	}

	s.AllowRead = append(s.AllowRead, extraRead...)
	s.AllowWrite = append(s.AllowWrite, extraWrite...)
	return s
}

// AllowSocketPath adds the daemon socket as the single connectable door.
func (s Spec) AllowSocketPath(sock string) Spec {
	if sock != "" {
		s.AllowSocket = append(s.AllowSocket, filepath.Clean(sock))
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

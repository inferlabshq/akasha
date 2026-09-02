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
	// denyOn is deny for a path that only exists on one platform. See Rule.OS:
	// rendering a macOS path on Linux aborted the launch for every non-root
	// user, and created the directory when it did not.
	denyOn := func(goos, path string, tree bool, why string) {
		if path == "" {
			return
		}
		s.Deny = append(s.Deny, Rule{Path: filepath.Clean(path), Tree: tree, Mode: DenyAll, Why: why, OS: goos})
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
	denyOn("darwin", "/Volumes/akasha-sessions", true, "macOS RAM disk holding materialized session credentials")
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		deny(filepath.Join(x, "akasha"), true, "session credentials (tmpfs)")
	}
	// Linux-only, and tagged as such now the render plan makes the omission
	// visible: macOS materializes session credentials on the /Volumes RAM disk
	// above, and /dev/shm does not exist there at all.
	denyOn("linux", filepath.Join("/dev/shm", "akasha-"+itoa(os.Getuid())), true, "session credentials (tmpfs)")

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
		denyOn("darwin", filepath.Join(home, "Library/Keychains"), true, "macOS keychain files")

		// akasha's OWN key, in the files akasha itself wrote it into. This was
		// the gap that made the capability profile bypassable — see
		// agentkey.go for the measurement and for why masking is the only
		// portable fix.
		for _, t := range AgentKeyFiles(home) {
			why := "akasha agent key (setup injects AKASHA_AGENT_KEY here)"
			if t.goos == "" {
				deny(t.path, false, why)
				continue
			}
			denyOn(t.goos, t.path, false, why)
		}
	}
	denyOn("darwin", "/Library/Keychains", true, "macOS system keychain files")

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
		// over SSH_AUTH_SOCK — the same architecture akasha uses, where the
		// secret stays with the broker.
		for _, rel := range []string{".ssh/config", ".ssh/known_hosts"} {
			s.AllowReadTry = append(s.AllowReadTry, filepath.Join(home, rel))
		}
	}

	// The ssh-agent socket, held open explicitly.
	//
	// "allow-by-default already permits it" stopped being true the moment the
	// keychain masks landed: gnome-keyring serves ssh-agent from
	// $XDG_RUNTIME_DIR/keyring/ssh, and both the runtime directory and the
	// keyring directory are masked above. So every `git push` over agent auth
	// failed inside `akasha run` — and `akasha run` is the ONLY mechanism the
	// behavioural test found that gets a model to broker at all. A sandbox that
	// breaks push is a sandbox users turn off.
	//
	// Allowing it back is consistent rather than a concession. An agent socket
	// is a BROKER: it signs a challenge and never yields the private key, which
	// is the USE-not-READ line this whole product is drawn along. Denying it
	// would not protect the key — the key stays in ssh-agent either way — it
	// would only push the user toward an unprotected key file.
	//
	// It is a hole in the keyring mask, and a narrow one: the path is the agent
	// socket only, so $XDG_RUNTIME_DIR/keyring/control — the Secret Service
	// channel that actually hands out the vault's key — stays masked beside it.
	// Two guards, because this is the one door in the surface whose PATH comes
	// from the environment rather than from this function.
	//
	// validPath on the RAW value, never on a cleaned one: cleaning first is what
	// made SSH_AUTH_SOCK=/tmp/../etc/shadow acceptable, since Clean had already
	// removed the ".." that validPath refuses. The cleaning was mine and it
	// disarmed the check I was calling.
	//
	// And it must BE a socket. Without that, SSH_AUTH_SOCK naming a regular file
	// inside a denied tree — ~/.aws/credentials, say — would bind that file back
	// through the mask and hand the child exactly what the deny exists to hide.
	// Requiring a socket keeps the door open for the people who really do keep
	// an agent at ~/.ssh/agent.sock while making the exfiltration spelling
	// impossible: a socket has no bytes to read, only a protocol to speak, which
	// is the same USE-not-READ line akasha itself is drawn along.
	//
	// RESIDUAL: stat and mount are two moments, so a socket swapped for a file
	// in between would still be bound. Closing that needs the mount to happen on
	// a descriptor rather than a path, which bwrap's CLI cannot express. It costs
	// nothing to an attacker who is already the same uid — the ceiling this
	// whole surface sits under — and it is written down rather than implied.
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" && validPath(sock, "ssh-agent") == nil {
		if fi, err := os.Stat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			s.AllowSocketTry = append(s.AllowSocketTry, sock)
		}
	}

	s.AllowRead = append(s.AllowRead, extraRead...)
	s.AllowWrite = append(s.AllowWrite, extraWrite...)
	return s
}

// AllowSocketPath adds the daemon socket as the single connectable door.
// DenyingCredentialSources masks the files this machine's credentials were
// actually discovered from.
//
// The static list above covers the well-known stores — ~/.aws, ~/.ssh, ~/.netrc
// and the rest — and akasha's own templates declare sixteen places a credential
// can live. Fourteen were not on it: every shell startup file, and every .env
// glob. Measured: an AWS key seeded into ~/.zshrc and ~/.env was flagged by
// `akasha discover` as a credential and read straight out of both from inside
// the sandbox.
//
// Masking every declared location would be worse than the gap. Those globs
// cover ~/.env and ~/projects/.env*, and the shell files that set up PATH:
// masking them breaks the application the agent was launched to work on, and
// the shell it works in. A sandbox that has to be switched off to get anything
// done protects nothing.
//
// So the list is derived from PROVENANCE instead. Discovery records where each
// credential came from, so the vault knows which of those files hold a secret
// on this machine: a .env with a vaulted credential is masked, a .env with
// application config is untouched. Nothing here is maintained by hand, so a new
// template's discover block is covered the day it lands.
//
// A file is masked as a FILE, never as a tree. These are ordinary paths a user
// chose, and one of them being a directory would otherwise take an entire
// project with it.
func (s Spec) DenyingCredentialSources(paths []string) Spec {
	for _, p := range paths {
		if p == "" || !filepath.IsAbs(p) {
			continue
		}
		s.Deny = append(s.Deny, Rule{
			Path: filepath.Clean(p),
			Mode: DenyAll,
			Why:  "a credential was discovered here and is in the vault",
		})
	}
	return s
}

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

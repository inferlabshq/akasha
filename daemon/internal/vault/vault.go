package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	keyring "github.com/zalando/go-keyring"
	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo → static cross-platform binaries)

	vaultcrypto "github.com/inferlabshq/akasha/daemon/internal/crypto"
)

// cryptoRandRead is a package-level var so tests can stub it.
var cryptoRandRead = rand.Read

// Agent-key verification errors. These are sentinels so callers can tell apart
// the two reasons a key is rejected — a distinction that matters because the
// safe response differs:
//
//   - ErrAgentKeyInvalid: the key isn't in the registry. Usually a desync (the
//     config holds a key the vault no longer knows, e.g. after a vault rebuild),
//     which is safe to repair by re-minting.
//   - ErrAgentKeyRevoked: the key was deliberately revoked. Re-minting it would
//     defeat revocation, so this must NEVER be auto-repaired.
//
// VerifyAgentKey cannot tell which case a caller is in from the wire, so it
// reports them distinctly and leaves the policy decision to the caller.
var (
	ErrAgentKeyInvalid = errors.New("invalid agent key")
	ErrAgentKeyRevoked = errors.New("agent key revoked")
)

const (
	tokenPrefix = "vault://"
	grantPrefix = "grt://"

	// Keychain accounts
	keyringMLKEMSK = "vault-mlkem-sk" // ML-KEM decapsulation key (secret)
)

// keyringService is the OS-keychain service the vault key lives under.
//
// Under `go test` it is automatically pointed at an isolated entry: a fresh-DB
// vault.Open regenerates and stores the ML-KEM key, so if tests (in ANY package)
// shared the production service they would overwrite the real "akasha-daemon"
// key and break the daemon on its next restart. Auto-detecting the test binary
// here isolates every package's tests without per-package boilerplate.
var keyringService = func() string {
	if isTestBinary() {
		// Per-PID so parallel `go test ./...` package binaries don't race the
		// same keychain entry. Tests reconstruct this name (same PID) to clean
		// it up in TestMain.
		return fmt.Sprintf("akasha-test-%d", os.Getpid())
	}
	return "akasha-daemon"
}()

// KeychainProbe returns the (service, account) pair the vault reads its key
// from, so the sandbox self-test can verify that exact lookup is blocked rather
// than guessing at the names. Exported because a self-test that probes a
// DIFFERENT keychain item than the vault actually uses would pass while the
// real one stayed reachable.
func KeychainProbe() (service, account string) { return keyringService, keyringMLKEMSK }

// Under test, use an in-memory keyring by default.
//
// Opening a vault requires a credential store, so a headless Linux runner — no
// Secret Service, "org.freedesktop.secrets was not provided by any .service
// files" — would fail every test in every package that opens one, while all of
// them passed on a developer's Mac. Green where written, red where gated.
//
// This lives beside the vault rather than in each package's TestMain because
// several packages open vaults; a per-package fix is several places to forget.
// It is gated on isTestBinary, the same guard that already redirects
// keyringService under test, so a shipped binary never takes this path.
//
// The default used to be the HOST keyring wherever one existed, on the
// reasoning that production uses a real one. In practice that made an ordinary
// `go test ./...` write to the developer's login keychain hundreds of times —
// once per vault created, across package binaries Go runs in PARALLEL — and it
// cost more than it bought:
//
//   - macOS put up a modal "A keychain cannot be found to store vault-mlkem-sk"
//     mid-run, on a machine whose vault key had just been recovered.
//   - Contention produced a flaky 500 in an unrelated server test that passed
//     whenever the package ran on its own.
//   - Linux CI has no Secret Service, so it ran the mock anyway — the "preferred"
//     path was never the one gating merges.
//
// The failures a real keyring would catch are environmental — a locked
// collection, a denied ACL prompt, a session bus that isn't there — and an
// in-process test cannot exercise those regardless. The ones that matter for
// akasha's own messages are faked directly instead (see credstore.go), which
// covers them on every platform rather than only where a store exists.
// AKASHA_TEST_REAL_KEYRING=1 opts back in for anyone who wants it.
func init() {
	if !isTestBinary() {
		return
	}
	if os.Getenv("AKASHA_TEST_REAL_KEYRING") == "1" {
		// Verify the host actually has a usable store; fall back rather than
		// failing every vault test on a machine that has none.
		const probeSvc, probeAcct = "akasha-keyring-probe", "probe"
		if err := keyring.Set(probeSvc, probeAcct, "x"); err == nil {
			keyring.Delete(probeSvc, probeAcct)
			return
		}
	}
	keyring.MockInit()
}

// isTestBinary reports whether the process is a `go test` binary (named
// "<pkg>.test"), so the vault can use an isolated keychain entry.
func isTestBinary() bool {
	arg0 := os.Args[0]
	return strings.HasSuffix(arg0, ".test") ||
		strings.HasSuffix(arg0, ".test.exe") ||
		strings.Contains(arg0, "/T/go-build") // `go test` temp build dir
}

// ─── Public types ─────────────────────────────────────────────────────────

type Entry struct {
	Token          string
	Category       string
	Risk           string
	AgentID        string
	ToolName       string
	CreatedAt      time.Time
	ExpiresAt      *time.Time
	RetrievedCount int
}

type Grant struct {
	GrantID      string
	Token        string
	GrantorAgent string
	GranteeAgent string
	AllowedTool  string
	Task         string
	CreatedAt    time.Time
	ExpiresAt    *time.Time
	UsedAt       *time.Time
}

// ─── Vault ────────────────────────────────────────────────────────────────

type Vault struct {
	db         *sql.DB
	dbPath     string // for error messages that must name which vault is meant
	currentKey []byte // XChaCha20-Poly1305 key (ML-KEM derived)
}

// Options configures vault behaviour at open time.
type Options struct {
	// Passphrase, if non-nil, is folded into the vault key via Argon2id.
	// The vault cannot be opened without the same passphrase in future runs.
	Passphrase []byte

	// AllowNewVaultKey permits creating a vault whose new key REPLACES the one
	// already in this machine's keychain, making any existing vault
	// undecryptable. Off by default; see the guard in resolveKeys.
	//
	// Defaulted from AKASHA_ALLOW_NEW_VAULT=1 so the escape hatch reaches every
	// entry point (start, setup, the SDK) without threading a flag through each,
	// and so opting in is a deliberate act rather than a mistyped path.
	AllowNewVaultKey bool
}

// Open opens (or creates) the vault at dbPath.
// restrictVaultFiles tightens the database file set to 0600. Best-effort: a
// vault on a filesystem without unix modes still has to open.
func restrictVaultFiles(dbPath string) {
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm()&0o077 == 0 {
			continue
		}
		os.Chmod(p, 0600)
	}
}

func Open(dbPath string, opts Options) (*Vault, error) {
	// Sampled BEFORE sql.Open, which creates the file. Asking afterwards
	// always answers "yes" and the check becomes decoration — the same trap the
	// uninstall purge guard fell into, one directory over.
	existed := fileWasThere(dbPath)

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}

	// Before migrate, which CREATES the tables whose absence is the evidence.
	if err := checkIntact(db, dbPath, existed); err != nil {
		db.Close()
		return nil, err
	}

	v := &Vault{db: db, dbPath: dbPath}
	if err := v.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// SQLite creates the database and its WAL/SHM siblings with the process
	// umask, so under the common 022 they land 0644 — readable by every account
	// on the machine. The contents are encrypted, but the WAL carries the most
	// recent writes and the file set is a free copy of the ciphertext to attack
	// offline, so the mode is worth asserting rather than inheriting. migrate()
	// has run, so the WAL exists by now.
	restrictVaultFiles(dbPath)

	// The escape hatch is read here so it applies to every entry point.
	if os.Getenv("AKASHA_ALLOW_NEW_VAULT") == "1" {
		opts.AllowNewVaultKey = true
	}

	currentKey, err := v.resolveKeys(opts)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("key setup: %w", err)
	}
	v.currentKey = currentKey
	return v, nil
}

// Checkpoint folds the write-ahead log back into the main database file.
//
// In WAL mode a write lands in vault.db-wal and STAYS there: SQLite only moves
// it across on its own once the log passes ~1000 pages, which a personal vault
// of a few dozen credentials never reaches. That is not a durability problem —
// the WAL is part of the database and replays after a crash — but it makes
// vault.db on its own an empty shell, and vault.db is the file a human copies.
// Every path that hands someone a copy of the database (backup, export,
// migration) therefore has to fold the log in first, and so does a clean stop.
//
// TRUNCATE is the mode that gives that guarantee: it blocks until every frame
// has been applied and then resets the log to zero bytes, so a copy taken
// afterwards cannot silently be missing recent writes. SQLite reports a refusal
// in the first result column rather than as an error, which is why it is
// checked — a busy checkpoint means the copy the caller is about to take is
// incomplete, and swallowing that is exactly the bug this exists to prevent.
func (v *Vault) Checkpoint() error {
	var busy, walFrames, applied int
	err := v.db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &walFrames, &applied)
	if err != nil {
		return fmt.Errorf("checkpoint %s: %w", v.dbPath, err)
	}
	if busy != 0 {
		return fmt.Errorf(
			"checkpoint %s: another connection is holding the vault open, so %d write-ahead frames "+
				"could not be folded into the database file.\n"+
				"  A copy of vault.db taken now would be missing them. Stop the daemon and retry.",
			v.dbPath, walFrames)
	}
	return nil
}

// Close checkpoints the WAL, then releases the database handle.
//
// The checkpoint is best-effort here and its error is deliberately dropped: a
// shutdown must not fail because something else still had the vault open, and
// nothing is lost when it does not run — the WAL remains part of the database.
// What it buys is that after a clean stop vault.db ALONE is the whole vault,
// which is what makes a backup or a copy taken while akasha is not running
// correct. Callers that are about to copy the file need the guarantee, not the
// attempt, and must call Checkpoint directly and handle its error.
func (v *Vault) Close() error {
	_ = v.Checkpoint()
	return v.db.Close()
}

// ─── Core operations ──────────────────────────────────────────────────────

func (v *Vault) Store(plaintext, category, risk, agentID, toolName string, ttl time.Duration) (string, error) {
	token := tokenPrefix + randomID(8)

	encrypted, err := vaultcrypto.Encrypt(v.currentKey, []byte(plaintext))
	if err != nil {
		return "", err
	}

	var expiresAt *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl).UTC()
		expiresAt = &t
	}

	_, err = v.db.Exec(`
		INSERT INTO vault (token, encrypted_value, category, risk, agent_id, tool_name, created_at, expires_at, cipher_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token, encrypted, category, risk, agentID, toolName,
		time.Now().UTC(), expiresAt, vaultcrypto.CipherXChaCha20,
	)
	return token, err
}

func (v *Vault) Retrieve(token, requestingTool string) (string, error) {
	plain, err := v.Peek(token)
	if err != nil {
		return "", err
	}
	v.db.Exec(`UPDATE vault SET retrieved_count = retrieved_count + 1 WHERE token = ?`, token)
	return plain, nil
}

// Peek decrypts an entry WITHOUT counting the read as a retrieval.
//
// It exists for the daemon's own guards, which read an entry to answer a
// question ABOUT it rather than to hand it to anyone — the escrow guard
// compares the stored envelope with the file on disk before allowing a name to
// be removed or re-pointed. `retrieved_count` answers "how many times has this
// secret left the vault", and it is the number a reviewer scans for a
// disclosure, so an internal comparison must not push it up. Anything that
// returns a value to a caller uses Retrieve.
func (v *Vault) Peek(token string) (string, error) {
	if !strings.HasPrefix(token, tokenPrefix) {
		return "", fmt.Errorf("invalid token format")
	}

	var encrypted []byte
	var expiresAt *time.Time
	var cipherVersion int
	row := v.db.QueryRow(
		`SELECT encrypted_value, expires_at, cipher_version FROM vault WHERE token = ?`, token)
	if err := row.Scan(&encrypted, &expiresAt, &cipherVersion); err == sql.ErrNoRows {
		return "", fmt.Errorf("token not found")
	} else if err != nil {
		return "", err
	}

	if expiresAt != nil && time.Now().After(*expiresAt) {
		return "", fmt.Errorf("token expired")
	}

	plain, err := v.decrypt(encrypted, cipherVersion)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (v *Vault) Inspect(token string) (*Entry, error) {
	row := v.db.QueryRow(`
		SELECT token, category, risk, agent_id, tool_name, created_at, expires_at, retrieved_count
		FROM vault WHERE token = ?`, token)

	var e Entry
	if err := row.Scan(&e.Token, &e.Category, &e.Risk, &e.AgentID, &e.ToolName,
		&e.CreatedAt, &e.ExpiresAt, &e.RetrievedCount); err == sql.ErrNoRows {
		return nil, fmt.Errorf("token not found")
	} else if err != nil {
		return nil, err
	}
	return &e, nil
}

func (v *Vault) Stats() (total, expired int, err error) {
	v.db.QueryRow(`SELECT COUNT(*) FROM vault`).Scan(&total)
	v.db.QueryRow(`SELECT COUNT(*) FROM vault WHERE expires_at IS NOT NULL AND expires_at < ?`,
		time.Now()).Scan(&expired)
	return
}

// PurgeExpired deletes vault entries and grants that have passed their TTL.
// Call this periodically (e.g. every hour) from a background goroutine.
func (v *Vault) PurgeExpired() (int, error) {
	now := time.Now().UTC()
	res, err := v.db.Exec(
		`DELETE FROM vault WHERE expires_at IS NOT NULL AND expires_at < ?`, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	// Also purge expired grants.
	v.db.Exec(`DELETE FROM grants WHERE expires_at IS NOT NULL AND expires_at < ?`, now)
	return int(n), nil
}

// discoveryTool is how a vault entry says it came from credential discovery.
//
// It used to be matched on agent_id against "akasha-setup"/"akasha-discover",
// and it never matched anything. Those are the names the provisioning client
// DECLARES in the request body, but /store writes the AUTHENTICATED identity —
// `cli` for the human running discovery — so the sweep selected zero rows and
// reported {"purged":0} forever while the vault grew on every run. Measured: 30
// discoveries left 155 entries for 2 labels, 2.68 MB, with no command able to
// clean them.
//
// tool_name is the field that actually survives the round trip: the provisioning
// client sets it and /store passes it through verbatim. Matching on it means the
// sweep sees what it was always meant to see.
//
// Entries created this way are only ever meant to be reachable through a label,
// profile or grant, so an unreachable one is a leftover from re-running
// discovery and is safe to collect. Secrets stored by real agents carry their
// own tool name and are never touched.
const discoveryTool = "akasha_provision"

// purgeGracePeriod keeps the sweep away from entries that may still be between
// their /store and their /label/set. See the note in PurgeOrphans.
//
// Sixty seconds, and the first attempt at ten minutes was wrong in a way worth
// recording. The reasoning then was "far longer than the gap it protects, far
// shorter than the interval between discovery runs" — and the second half is
// simply false. Someone trying the tool runs `akasha discover` several times in
// a few minutes, and every one of those sweeps then collected nothing:
// six back-to-back runs left 108 rows, exactly the number the broken selector
// used to leave. The bug the sweep exists to fix came back in full for the
// person most likely to meet it, and only healed on a run more than ten minutes
// later, because PurgeOrphans has no other caller and no timer.
//
// What the window actually has to cover is much smaller than either figure. The
// sweep runs from the SAME process that has just finished binding its own
// findings, so its own entries are reachable by then; the only thing at risk is
// a CONCURRENT discovery, whose store→bind gap is one socket round trip per
// finding. A minute is three orders of magnitude more than that and still short
// enough that a re-run collects.
var purgeGracePeriod = 60 * time.Second

// discoveryAgents is kept for vaults written before the tool_name match existed,
// so a sweep on an old database still finds their leftovers.
var discoveryAgents = []string{"akasha-setup", "akasha-discover"}

// PurgeOrphans garbage-collects credential entries left behind by repeated
// discovery runs. Discovery mints a fresh credential-map token (plus its
// underlying field tokens) every time it runs and re-points the label at the
// new token via SetLabel, orphaning the old chain. This sweep marks every
// vault token reachable from a label, profile, or grant — following one level
// of {field: token} credential-map indirection — and deletes any
// discovery-created entry that is no longer reachable.
//
// It is idempotent: running discovery N times then calling PurgeOrphans leaves
// the same number of entries as running it once.
func (v *Vault) PurgeOrphans() (int, error) {
	reachable, err := v.reachableTokens()
	if err != nil {
		return 0, err
	}

	placeholders := make([]string, len(discoveryAgents))
	args := make([]interface{}, len(discoveryAgents))
	for i, a := range discoveryAgents {
		placeholders[i] = "?"
		args[i] = a
	}
	// Nothing younger than the grace window, because "unreachable" and "not
	// bound YET" look identical.
	//
	// Discovery stores a credential and then names it, in two calls. A sweep
	// landing between them sees a token no label points at, deletes it, and the
	// bind that follows succeeds — returning 200 for a name that now resolves to
	// nothing. That race existed all along and could never fire while this
	// collector selected zero rows; making it work is what armed it.
	//
	// A window rather than a lock, because the two calls come from a separate
	// process over a socket: there is no transaction to join, and a lock held
	// across a client round trip is its own hazard. Ten minutes is far longer
	// than the gap it protects (milliseconds) and far shorter than the interval
	// between discovery runs, so it costs one sweep's worth of garbage at most.
	//
	// tool_name is the reliable discriminator; the agent_id list is the
	// compatibility tail for entries written before that was true.
	// A time.Time, not a formatted string: Store writes created_at as a
	// time.Time and the driver picks the serialization, so a hand-rolled
	// RFC3339 on this side compares against a different shape and never
	// matches — the window would silently do nothing.
	args = append(args, discoveryTool, time.Now().Add(-purgeGracePeriod).UTC())
	rows, err := v.db.Query(
		`SELECT token FROM vault
		   WHERE (agent_id IN (`+strings.Join(placeholders, ",")+`) OR tool_name = ?)
		     AND created_at < ?`,
		args...)
	if err != nil {
		return 0, err
	}
	var toDelete []string
	for rows.Next() {
		var tok string
		if err := rows.Scan(&tok); err != nil {
			rows.Close()
			return 0, err
		}
		if !reachable[tok] {
			toDelete = append(toDelete, tok)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, tok := range toDelete {
		if _, err := v.db.Exec(`DELETE FROM vault WHERE token = ?`, tok); err != nil {
			return 0, err
		}
	}
	return len(toDelete), nil
}

// CountNonDiscovered returns the number of live (non-expired) vault entries that
// were NOT created by the discovery flows — i.e. secrets an agent wrapped via
// the proxy whose only surviving copy is the vault. Discovered credentials
// (AWS/SSH/Git) are excluded because they can be re-scanned from their original
// source; these cannot. Used by `akasha uninstall` to warn before a purge.
func (v *Vault) CountNonDiscovered() (int, error) {
	placeholders := make([]string, len(discoveryAgents))
	args := make([]interface{}, 0, len(discoveryAgents)+1)
	for i, a := range discoveryAgents {
		placeholders[i] = "?"
		args = append(args, a)
	}
	args = append(args, time.Now().UTC())
	var n int
	err := v.db.QueryRow(
		`SELECT COUNT(*) FROM vault
		 WHERE agent_id NOT IN (`+strings.Join(placeholders, ",")+`)
		   AND (expires_at IS NULL OR expires_at > ?)`, args...,
	).Scan(&n)
	return n, err
}

// reachableTokens returns the set of vault tokens reachable from any label,
// profile, or grant root, following one level of credential-map indirection
// (a root blob of the form {"field": "vault://..."} marks its referenced
// underlying tokens as reachable too).
func (v *Vault) reachableTokens() (map[string]bool, error) {
	reachable := map[string]bool{}

	var roots []string
	collect := func(query string) error {
		rows, err := v.db.Query(query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var tok string
			if err := rows.Scan(&tok); err != nil {
				return err
			}
			roots = append(roots, tok)
		}
		return rows.Err()
	}
	if err := collect(`SELECT token FROM labels`); err != nil {
		return nil, err
	}
	if err := collect(`SELECT token FROM profiles`); err != nil {
		return nil, err
	}
	if err := collect(`SELECT token FROM grants`); err != nil {
		return nil, err
	}

	for _, root := range roots {
		if reachable[root] {
			continue
		}
		reachable[root] = true
		// A root is usually a credential-map blob mapping field → vault token.
		// Decrypt it and mark any referenced underlying tokens as reachable.
		plain, err := v.peek(root)
		if err != nil {
			continue // unreadable or already gone — nothing to follow
		}
		var m map[string]string
		if json.Unmarshal([]byte(plain), &m) != nil {
			continue
		}
		for _, ref := range m {
			if strings.HasPrefix(ref, tokenPrefix) {
				reachable[ref] = true
			}
		}
	}
	return reachable, nil
}

// peek decrypts a token's value without incrementing its retrieved_count or
// triggering lazy re-encryption. Used by internal bookkeeping like GC.
func (v *Vault) peek(token string) (string, error) {
	var encrypted []byte
	var cipherVersion int
	row := v.db.QueryRow(
		`SELECT encrypted_value, cipher_version FROM vault WHERE token = ?`, token)
	if err := row.Scan(&encrypted, &cipherVersion); err != nil {
		return "", err
	}
	plain, err := v.decrypt(encrypted, cipherVersion)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ─── Grant system (A2A cross-agent delegation) ────────────────────────────

func (v *Vault) CreateGrant(token, grantorAgent, granteeAgent, allowedTool, task string, ttl time.Duration) (string, error) {
	if _, err := v.Inspect(token); err != nil {
		return "", fmt.Errorf("cannot grant unknown token: %w", err)
	}
	grantID := grantPrefix + randomID(12)
	var expiresAt *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl).UTC()
		expiresAt = &t
	}
	_, err := v.db.Exec(`
		INSERT INTO grants (grant_id, token, grantor_agent, grantee_agent, allowed_tool, task, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		grantID, token, grantorAgent, granteeAgent, allowedTool, task, time.Now().UTC(), expiresAt,
	)
	return grantID, err
}

func (v *Vault) RedeemGrant(grantID, claimingAgent, requestedTool string) (string, error) {
	if !strings.HasPrefix(grantID, grantPrefix) {
		return "", fmt.Errorf("invalid grant format")
	}
	var token, granteeAgent, allowedTool string
	var expiresAt, usedAt *time.Time
	row := v.db.QueryRow(
		`SELECT token, grantee_agent, allowed_tool, expires_at, used_at FROM grants WHERE grant_id = ?`, grantID)
	if err := row.Scan(&token, &granteeAgent, &allowedTool, &expiresAt, &usedAt); err == sql.ErrNoRows {
		return "", fmt.Errorf("grant not found")
	} else if err != nil {
		return "", err
	}
	if usedAt != nil {
		return "", fmt.Errorf("grant already redeemed at %s", usedAt.Format(time.RFC3339))
	}
	if expiresAt != nil && time.Now().After(*expiresAt) {
		return "", fmt.Errorf("grant expired")
	}
	if granteeAgent != "" && granteeAgent != claimingAgent {
		return "", fmt.Errorf("grant issued to %q, not %q", granteeAgent, claimingAgent)
	}
	if allowedTool != "" && allowedTool != requestedTool {
		return "", fmt.Errorf("grant restricted to tool %q", allowedTool)
	}
	// Atomically claim the grant. The `used_at IS NULL` guard means only the
	// first of any concurrent redemptions affects a row, so a single-use grant
	// cannot be redeemed twice even under a race. The write error and the claim
	// count are both checked, so a failed mark-as-used never returns the token.
	now := time.Now().UTC()
	res, err := v.db.Exec(`UPDATE grants SET used_at = ? WHERE grant_id = ? AND used_at IS NULL`, now, grantID)
	if err != nil {
		return "", err
	}
	claimed, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	if claimed == 0 {
		return "", fmt.Errorf("grant already redeemed")
	}
	return token, nil
}

func (v *Vault) InspectGrant(grantID string) (*Grant, error) {
	row := v.db.QueryRow(`
		SELECT grant_id, token, grantor_agent, grantee_agent, allowed_tool, task, created_at, expires_at, used_at
		FROM grants WHERE grant_id = ?`, grantID)
	var g Grant
	if err := row.Scan(&g.GrantID, &g.Token, &g.GrantorAgent, &g.GranteeAgent,
		&g.AllowedTool, &g.Task, &g.CreatedAt, &g.ExpiresAt, &g.UsedAt); err == sql.ErrNoRows {
		return nil, fmt.Errorf("grant not found")
	} else if err != nil {
		return nil, err
	}
	return &g, nil
}

// ─── Crypto helpers ───────────────────────────────────────────────────────

func (v *Vault) decrypt(data []byte, cipherVersion int) ([]byte, error) {
	switch cipherVersion {
	case vaultcrypto.CipherXChaCha20:
		return vaultcrypto.Decrypt(v.currentKey, data)
	default:
		return nil, fmt.Errorf("unknown cipher version %d", cipherVersion)
	}
}

// ─── Key resolution ───────────────────────────────────────────────────────

// resolveKeys loads or generates vault keys on startup.
//
// Priority:
//  1. ML-KEM sk + KEM ciphertext from DB → derive currentKey
//  2. If not present: generate ML-KEM keypair, encapsulate, store, derive
//  3. Passphrase (if provided) → Argon2id → fold into currentKey
func (v *Vault) resolveKeys(opts Options) (currentKey []byte, err error) {
	// ── Try ML-KEM path ──
	// This vault's own account, which for a vault created before ids existed is
	// the original shared name — see vaultid.go. Resolved BEFORE the read, so a
	// vault with an id never consults another vault's entry.
	account, err := v.keychainAccount()
	if err != nil {
		// Refusing beats guessing. The fallback used to be the shared legacy
		// account, so an unreadable database made this vault read, and later
		// overwrite, a key that may belong to a different vault entirely.
		return nil, fmt.Errorf("cannot determine which keychain entry holds this vault's key: %w.\n"+
			"  Refusing to fall back to the shared account name, because on a machine with an\n"+
			"  older vault that entry belongs to it.", err)
	}
	dkEncoded, kemErr := keyringGet(keyringService, account)
	kemCT, ctErr := v.getMetadata("kem_ciphertext")

	if kemErr == nil && ctErr == nil {
		// Both present — normal startup.
		dkBytes, err := base64.StdEncoding.DecodeString(dkEncoded)
		if err != nil {
			return nil, fmt.Errorf("decode mlkem sk: %w", err)
		}
		ct, err := base64.StdEncoding.DecodeString(kemCT)
		if err != nil {
			return nil, fmt.Errorf("decode kem ct: %w", err)
		}
		ss, err := vaultcrypto.MLKEMDecaps(dkBytes, ct)
		if err != nil {
			return nil, fmt.Errorf("mlkem decaps: %w", err)
		}
		currentKey, err = vaultcrypto.DeriveVaultKey(ss)
		if err != nil {
			return nil, err
		}
	} else if ctErr == nil {
		// CRITICAL: the vault already has key material (kem_ciphertext exists),
		// but the keychain key is unreadable. This is NOT a fresh vault — the
		// existing entries are encrypted under a key we can no longer reach.
		// Generating a new key here would silently orphan all vault data.
		// Fail loudly instead and tell the user how to recover.
		//
		// The recovery advice names both platforms. Naming only the macOS cause
		// sent Linux users down the wrong road entirely: there the reason is
		// almost always a Secret Service that is not running or not unlocked,
		// the key is still sitting in it, and `akasha vault restore` is neither
		// necessary nor a thing to suggest lightly. Listing both unconditionally
		// matches the sibling guard below; the platform is the one thing the
		// reader already knows, and branching on runtime.GOOS would hide the
		// other half from anyone diagnosing a machine remotely.
		return nil, fmt.Errorf(
			"vault is locked: encryption key not found in this machine's credential store (%v).\n"+
				"  This vault already contains encrypted data. A new key was NOT generated.\n"+
				"  Linux: a Secret Service (e.g. gnome-keyring) is not running or is locked —\n"+
				"    start and unlock it, then retry. The key itself is almost certainly intact.\n"+
				"    If akasha already woke a locked keyring this session, kill it first\n"+
				"    (pkill -f gnome-keyring-daemon); unlocking afterwards does not take.\n"+
				"  macOS: the login keychain is locked, or this process is not looking at it.\n"+
				"    A different login session, or HOME pointing elsewhere, drops the login\n"+
				"    keychain out of the search list entirely. Unlock it, and check HOME.\n"+
				"  If the key really is gone, re-install it from a backup:\n"+
				"      akasha vault restore <backup.akb>",
			kemErr)
	} else {
		// kem_ciphertext is absent. Normally this means a genuinely fresh vault,
		// so we generate a new keypair below. But "no ciphertext" alone is NOT
		// proof of freshness: if the ciphertext metadata was lost while encrypted
		// rows survived (e.g. a botched purge that deleted the keychain key + the
		// kem_ciphertext row but left the vault table), generating a new key here
		// would silently orphan every existing entry under a key that can never
		// decrypt them — no error, just permanent data loss. The sibling guard
		// above only catches the inverse half-state, so check for rows here too.
		var existingRows int
		v.db.QueryRow(`SELECT COUNT(*) FROM vault`).Scan(&existingRows)
		if existingRows > 0 {
			return nil, fmt.Errorf(
				"vault is corrupt: %d encrypted entries exist but the KEM ciphertext is missing.\n"+
					"  A new key was NOT generated (that would permanently orphan those entries).\n"+
					"  Likely cause: an interrupted uninstall/purge removed key material but left data.\n"+
					"  Recover with:  akasha vault restore <backup.akb>\n"+
					"  Or, if these entries are disposable, delete the vault DB and start fresh.",
				existingRows)
		}

		// A key already exists on this machine, and this DB is not the vault it
		// belongs to. Generating here would `keyring.Set` straight over it and
		// leave the OTHER vault undecryptable — its rows intact, its key gone.
		//
		// The two guards above protect a vault's DATA from a bad key. This one
		// protects the machine's KEY from a new vault, which is the same
		// accident in the opposite direction and the one with no warning at
		// all: pointing --db at a path that does not exist silently rekeys the
		// machine. The damage is invisible until something restarts, because a
		// running daemon holds the old key in memory and keeps working.
		//
		// Refusing is right even when the existing key is genuinely orphaned:
		// we cannot tell an orphan from a live vault's key, and the cost of
		// being wrong is asymmetric — a clear error versus silent, permanent
		// loss of every credential in the other vault.
		// There are THREE states here, not two, and the difference between the
		// last two is a vault:
		//
		//   kemErr == nil            a key exists → refuse
		//   kemErr == ErrNotFound    no key exists → genuine first run, proceed
		//   kemErr == anything else  WE DO NOT KNOW → refuse
		//
		// The third case is the one that matters. keyring.Get returns
		// ErrNotFound only for genuine absence; a locked keychain, a denied ACL
		// prompt, a missing Secret Service or a dead D-Bus all return some other
		// error. Testing `kemErr == nil` alone treated every one of those as
		// "this machine has no key" and fell through to the keyring.Set below,
		// silently replacing a real key with a new one. Not knowing whether a
		// key is there has to fail the same way as knowing one is.
		if !opts.AllowNewVaultKey {
			if kemErr == nil {
				return nil, fmt.Errorf(
					"refusing to create a new vault at %s: this machine's keychain already holds a vault key.\n"+
						"  Creating a vault here would REPLACE that key, making the vault it belongs to\n"+
						"  permanently undecryptable — and you would not notice until the next restart,\n"+
						"  because a running daemon keeps its key in memory.\n"+
						"  If you meant to open the existing vault, check --db (default: ~/.akasha/vault.db).\n"+
						"  If you really do want a second vault, back up the current key first\n"+
						"  (`akasha vault backup <file>`) and then re-run with AKASHA_ALLOW_NEW_VAULT=1.",
					v.dbPath)
			}
			// ErrNotFound is necessary but NOT sufficient, because on macOS it
			// is not a reliable fact: go-keyring maps any "could not be found"
			// from /usr/bin/security to ErrNotFound, and the CLI says that both
			// for a missing item and for a keychain it cannot reach. So an
			// unreachable login keychain looks exactly like a fresh machine —
			// and this is the branch that would then mint a key over the real
			// one. Round-trip the store before believing it.
			if errors.Is(kemErr, keyring.ErrNotFound) {
				if reachErr := StoreIsReachable(); reachErr != nil {
					return nil, fmt.Errorf(
						"refusing to create a new vault at %s: the credential store said this machine has no\n"+
							"  vault key, but it is not answering reliably (%v), so that answer cannot be trusted.\n"+
							"  A new key was NOT generated: if a key does exist, creating one now would REPLACE it\n"+
							"  and make that vault permanently undecryptable.\n%s\n"+
							"  If you are certain this machine holds no vault key, re-run with AKASHA_ALLOW_NEW_VAULT=1.",
						v.dbPath, reachErr, credentialStoreHelp)
				}
			}
			if !errors.Is(kemErr, keyring.ErrNotFound) {
				return nil, fmt.Errorf(
					"refusing to create a new vault at %s: this machine's credential store could not be read (%v).\n"+
						"  A new key was NOT generated. If a vault key already exists there, creating one\n"+
						"  now would REPLACE it and make that vault permanently undecryptable.\n"+
						"%s\n"+
						"  If you are certain this machine holds no vault key, re-run with AKASHA_ALLOW_NEW_VAULT=1.",
					v.dbPath, kemErr, credentialStoreHelp)
			}
		}

		// First run — generate ML-KEM keypair, encapsulate, store.
		kp, err := vaultcrypto.GenerateMLKEMKeypair()
		if err != nil {
			return nil, err
		}
		ct, ss, err := vaultcrypto.MLKEMEncaps(kp.EKBytes)
		if err != nil {
			return nil, err
		}
		currentKey, err = vaultcrypto.DeriveVaultKey(ss)
		if err != nil {
			return nil, err
		}
		// Mint this vault's id BEFORE the key, so the account name the key is
		// written to is the one the next open will look under. The reverse
		// order leaves a key at an account nothing derives.
		//
		// A crash after the id and before the key leaves an id with no key and
		// no ciphertext, which the next open treats as a fresh vault and
		// resolves by reusing the same id — see ensureVaultID.
		newID, err := v.ensureVaultID()
		if err != nil {
			return nil, err
		}
		account = accountFor(newID)

		// Store sk in keychain, ct in DB.
		//
		// This is the first thing a new Linux install fails on, and it used to
		// report only what go-keyring said — `exec: "dbus-launch": executable
		// file not found in $PATH` — which names a program the user never asked
		// for and no remedy at all. The ciphertext is written after this line,
		// so a failure here leaves the DB without one: nothing is half-created,
		// and saying so is what stops the reader reaching for `vault restore`.
		if err := keyringSet(keyringService, account,
			base64.StdEncoding.EncodeToString(kp.DKBytes)); err != nil {
			return nil, fmt.Errorf("could not store the vault key in this machine's credential store (%w).\n"+
				"  No vault was created, and nothing was lost — this is a setup step that has not run yet.\n%s",
				err, credentialStoreHelp)
		}
		if err := v.setMetadata("kem_ciphertext", base64.StdEncoding.EncodeToString(ct)); err != nil {
			return nil, fmt.Errorf("store kem ciphertext in db: %w", err)
		}
		if err := v.setMetadata("key_version", "2"); err != nil {
			return nil, err
		}
	}

	// ── Argon2id passphrase hardening ──
	//
	// The mode is checked BEFORE the fold, so a vault that needs a passphrase
	// says so instead of deriving a different key and failing later on the
	// first entry read. That failure looks exactly like a corrupt vault, and
	// the obvious response to a corrupt vault — `akasha vault restore` — is the
	// one action that could actually destroy the data.
	if len(opts.Passphrase) == 0 && v.RequiresPassphrase() {
		return nil, errPassphraseRequired(v.dbPath)
	}
	if len(opts.Passphrase) > 0 {
		salt, err := v.loadOrCreateArgon2Salt()
		if err != nil {
			return nil, err
		}
		passphraseKey := vaultcrypto.DerivePassphraseKey(
			opts.Passphrase, salt, vaultcrypto.DefaultArgon2Params,
		)
		currentKey, err = vaultcrypto.CombineKeys(currentKey, passphraseKey)
		if err != nil {
			return nil, err
		}
		// Recorded only where the key is actually established, so the mode
		// cannot drift from what the key IS. Recording it does not weaken
		// anything — the key is derived from the passphrase either way; this
		// only decides which explanation a mismatch produces.
		if err := v.setKeyMode(KeyModeKeychainPassphrase); err != nil {
			return nil, err
		}
	}

	return currentKey, nil
}

func (v *Vault) loadOrCreateArgon2Salt() ([]byte, error) {
	encoded, err := v.getMetadata("argon2_salt")
	if err == nil {
		return base64.StdEncoding.DecodeString(encoded)
	}
	salt, err := vaultcrypto.NewArgon2Salt()
	if err != nil {
		return nil, err
	}
	if err := v.setMetadata("argon2_salt", base64.StdEncoding.EncodeToString(salt)); err != nil {
		return nil, err
	}
	return salt, nil
}

// ─── Agent key registry ───────────────────────────────────────────────────

// AgentKey is a registered agent API key entry.
type AgentKey struct {
	KeyID     string
	AgentID   string
	CreatedAt time.Time
	LastUsed  *time.Time
	Revoked   bool
}

// publicKeyID derives the non-secret handle for a key from its hash.
//
// The handle exists so a human can name a key — to `akasha agent revoke` it, or
// to read it in `akasha agent list` — without that name BEING the key. It is
// derived from the hash rather than stored separately so it is reproducible for
// any key we can verify, including one re-admitted from an IDE config.
//
// 48 bits of a SHA-256 over a 192-bit random key: not reversible, and the
// birthday bound sits around 16M keys, far past any realistic registry. The
// column is a PRIMARY KEY, so a collision would surface as a failed insert
// rather than a silent overwrite.
func publicKeyID(hash string) string {
	if len(hash) > 12 {
		hash = hash[:12]
	}
	return "ak_" + hash
}

// IdentityCLI is the reserved agent identity of the local human CLI.
//
// It is an identity like any other — it holds a key, it appears in `agent
// list`, it can be revoked — which is the entire point. Privilege that used to
// follow from presenting NO key now follows from presenting THIS one, so the
// daemon grants the human path on an affirmative identity rather than on an
// absence it cannot verify. See ReservedAgentID for why it cannot be minted.
const IdentityCLI = "cli"

// RunIdentityPrefix namespaces the per-run identities `akasha run` mints. Like
// IdentityCLI these are server-assigned, so policy rules may be written against
// them; a key a caller minted for itself must never land in the namespace.
const RunIdentityPrefix = "run:"

// ReservedAgentID reports whether an agent identity is one the daemon assigns
// itself, and why it is refused to callers.
//
// Reserved names carry authority: the daemon grants the raw-secret human path
// to IdentityCLI, and policy rules are written against `run:` identities. If
// `akasha agent create cli` could mint a key bearing a reserved name, an agent
// would self-promote to the human simply by asking for the right string — which
// is the same defect as the keyless-is-human assumption this replaces, one
// layer down.
//
// This lives in the vault rather than in the daemon because `agent create`
// opens the vault DIRECTLY, without going through the socket. A check in the
// HTTP layer would not be on the path that mints keys.
func ReservedAgentID(agentID string) (bool, string) {
	id := strings.ToLower(strings.TrimSpace(agentID))
	switch {
	case id == IdentityCLI:
		return true, fmt.Sprintf("%q is the local CLI's own identity, provisioned by the daemon at startup", IdentityCLI)
	case strings.HasPrefix(id, RunIdentityPrefix):
		return true, fmt.Sprintf("the %q prefix is assigned by `akasha run` to a supervised run", RunIdentityPrefix)
	}
	return false, ""
}

// errReserved builds the refusal shared by the mint and re-admit paths.
func errReserved(agentID, why string) error {
	return fmt.Errorf("agent identity %q is reserved: %s, and a key minted for it would inherit that authority", agentID, why)
}

// CreateAgentKey generates a new API key for an agent, stores its hash and a
// non-secret handle, and returns both. The plaintext key is shown once and is
// NOT recoverable afterwards.
//
// The handle and the key used to be the same string ("the key IS the keyID"),
// which meant `agent list` printed every live bearer credential and the
// key_hash column was a hash of the value in the column beside it. They are now
// separate: key_id names the key, key_hash authenticates it, and the plaintext
// exists only in this return value.
//
// Reserved identities are refused here; the daemon mints its own with
// MintReservedAgentKey.
func (v *Vault) CreateAgentKey(agentID string) (keyID, plaintext string, err error) {
	if reserved, why := ReservedAgentID(agentID); reserved {
		return "", "", errReserved(agentID, why)
	}
	return v.mintAgentKey(agentID)
}

// MintReservedAgentKey mints a key for an identity the DAEMON assigns — the CLI
// key at startup, a `run:` identity in handleRunBegin. It exists so the reserved
// check on CreateAgentKey guards the caller-reachable path without also blocking
// the daemon from issuing the very identities it reserves.
//
// Callers of this are daemon-internal by construction: it is reachable only from
// Go code inside the binary, never from a request body or a CLI argument.
func (v *Vault) MintReservedAgentKey(agentID string) (keyID, plaintext string, err error) {
	return v.mintAgentKey(agentID)
}

func (v *Vault) mintAgentKey(agentID string) (keyID, plaintext string, err error) {
	// Key format: agt_<sanitized-agentid>_<32 chars from 24 random bytes>
	suffix := randomID(24)
	safe := strings.NewReplacer(" ", "-", "/", "-", ":", "-").Replace(agentID)
	if len(safe) > 16 {
		safe = safe[:16]
	}
	plaintext = "agt_" + safe + "_" + suffix

	hash := hashKey(plaintext)
	keyID = publicKeyID(hash)
	_, err = v.db.Exec(`
		INSERT INTO agent_keys (key_id, agent_id, key_hash, created_at)
		VALUES (?, ?, ?, ?)`,
		keyID, agentID, hash, time.Now().UTC(),
	)
	return keyID, plaintext, err
}

// RegisterAgentKey re-admits an already-existing key — one whose plaintext is
// known from a trusted local source, e.g. read back from an IDE's MCP config —
// into the registry. This is how `akasha agent resync` repairs a desynced key
// WITHOUT rotating it: the running MCP server keeps sending the same key, so the
// next tool call succeeds with no IDE restart.
//
// It deliberately refuses to un-revoke: if a row for this key still exists and
// is revoked, re-admitting would defeat a deliberate revocation, so it errors.
// If the row exists and is active, it's a no-op. If absent (the post-rebuild
// case, where the whole table — and thus the revocation state — was lost), it
// inserts. The trust root here is the local 0600 config file, which an attacker
// could only write with the user's own access; the daemon never auto-admits a
// key presented over the socket.
// Reserved identities are refused here as well as at mint time. Re-admission
// reads an agent id out of an IDE config file, so without this an agent that
// could write such a config would hand itself the CLI identity — arriving at
// the reserved name by the back door rather than through `agent create`.
func (v *Vault) RegisterAgentKey(agentID, plaintext string) error {
	if reserved, why := ReservedAgentID(agentID); reserved {
		return errReserved(agentID, why)
	}
	hash := hashKey(plaintext)
	var revoked int
	err := v.db.QueryRow(`SELECT revoked FROM agent_keys WHERE key_hash = ?`, hash).Scan(&revoked)
	switch {
	case err == nil:
		if revoked == 1 {
			return fmt.Errorf("key was revoked; re-mint a new one explicitly instead of re-admitting")
		}
		return nil // already active
	case err != sql.ErrNoRows:
		return err
	}
	// The handle is derived from the hash, never from the plaintext: this path
	// re-admits a key read out of an IDE config, so the plaintext is an
	// arbitrary caller-supplied string that must not end up in a column any
	// listing command prints.
	_, err = v.db.Exec(`
		INSERT INTO agent_keys (key_id, agent_id, key_hash, created_at)
		VALUES (?, ?, ?, ?)`,
		publicKeyID(hash), agentID, hash, time.Now().UTC(),
	)
	return err
}

// VerifyAgentKey looks up a key by its hash and returns the associated
// agent_id if valid. Updates last_used timestamp.
func (v *Vault) VerifyAgentKey(plaintext string) (agentID string, err error) {
	hash := hashKey(plaintext)
	var keyID string
	var revoked int
	err = v.db.QueryRow(
		`SELECT key_id, agent_id, revoked FROM agent_keys WHERE key_hash = ?`, hash,
	).Scan(&keyID, &agentID, &revoked)
	if err == sql.ErrNoRows {
		return "", ErrAgentKeyInvalid
	}
	if err != nil {
		return "", err
	}
	if revoked == 1 {
		return "", ErrAgentKeyRevoked
	}
	v.db.Exec(`UPDATE agent_keys SET last_used = ? WHERE key_id = ?`, time.Now().UTC(), keyID)
	return agentID, nil
}

// ListAgentKeys returns all registered agent keys.
func (v *Vault) ListAgentKeys() ([]*AgentKey, error) {
	rows, err := v.db.Query(
		`SELECT key_id, agent_id, created_at, last_used, revoked FROM agent_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AgentKey
	for rows.Next() {
		var k AgentKey
		var revoked int
		if err := rows.Scan(&k.KeyID, &k.AgentID, &k.CreatedAt, &k.LastUsed, &revoked); err != nil {
			return nil, err
		}
		k.Revoked = revoked == 1
		out = append(out, &k)
	}
	return out, rows.Err()
}

// RevokeAgentKey marks a key as revoked by key ID.
// RevokeAgentKeyByValue revokes the key with this plaintext, if it is
// registered. Used when a client's config is rewritten with a fresh key: the
// key being replaced is known by value, not by handle.
//
// A key that is not registered is not an error — the caller is asserting "this
// must not remain valid", and a key that was never valid already satisfies that.
func (v *Vault) RevokeAgentKeyByValue(plaintext string) error {
	if plaintext == "" {
		return nil
	}
	res, err := v.db.Exec(`UPDATE agent_keys SET revoked = 1 WHERE key_hash = ?`, hashKey(plaintext))
	if err != nil {
		return err
	}
	_, _ = res.RowsAffected()
	return nil
}

func (v *Vault) RevokeAgentKey(keyID string) error {
	res, err := v.db.Exec(`UPDATE agent_keys SET revoked = 1 WHERE key_id = ?`, keyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("key %q not found", keyID)
	}
	return nil
}

// ─── Key backup / restore ─────────────────────────────────────────────────

// BackupKey writes an encrypted backup of the vault key material to destPath.
// The backup contains the ML-KEM secret key + KEM ciphertext, encrypted with
// a key derived from the passphrase via Argon2id.
//
// It is the key and NOTHING ELSE: it holds no credential, so it can only unlock
// a vault.db you still have. Recovery needs both halves, and this file is the
// half that survives losing the machine. Whoever words the UI around this must
// say so — a user who reads "the only thing you need" copies vault.db without
// its write-ahead log and loses everything (see Checkpoint).
//
// Backup file format: [1 byte version][16 byte salt][xchacha20 sealed blob]
func (v *Vault) BackupKey(destPath string, passphrase []byte) error {
	// Gather key material: ML-KEM sk (keychain) + KEM ciphertext (DB).
	//
	// "There is no key" and "we could not ask" are different answers and the
	// second is the one that needs a remedy attached: on a Linux box with no
	// session bus this returned the raw `exec: "dbus-launch": executable file
	// not found in $PATH`, which reads like a missing key and sends the reader
	// looking for a backup they are in the middle of trying to make.
	acct, err := v.keychainAccount()
	if err != nil {
		return err
	}
	dkEncoded, err := keyringGet(keyringService, acct)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("no ML-KEM key to back up: %w", err)
		}
		return fmt.Errorf("could not read the vault key from this machine's credential store (%w).\n"+
			"  No backup was written. The key itself has not been touched — this is a\n"+
			"  read that could not happen, not a key that is gone.\n%s",
			err, credentialStoreHelp)
	}
	kemCT, err := v.getMetadata("kem_ciphertext")
	if err != nil {
		return fmt.Errorf("no KEM ciphertext: %w", err)
	}

	// vault_id travels WITH the key, so a restore knows which keychain account
	// to write it to even when the database is not there yet.
	//
	// Without it, restoring before putting vault.db back writes the key to the
	// legacy shared account, and the database — which knows its own id — then
	// looks under vault-mlkem-sk-<id> and reports the vault as locked. The key
	// would be on the machine the whole time, under the wrong name, and the
	// error would say nothing about it.
	//
	// Empty for a vault created before ids, which is what the legacy account
	// name means, so an old backup restored by a new binary still lands exactly
	// where it used to.
	material, err := json.Marshal(map[string]string{
		"mlkem_sk":       dkEncoded,
		"kem_ciphertext": kemCT,
		"vault_id":       v.vaultIDForDisplay(),
	})
	if err != nil {
		return err
	}

	salt, err := vaultcrypto.NewArgon2Salt()
	if err != nil {
		return err
	}
	wrapKey := vaultcrypto.DerivePassphraseKey(passphrase, salt, vaultcrypto.DefaultArgon2Params)
	sealed, err := vaultcrypto.Encrypt(wrapKey, material)
	if err != nil {
		return err
	}

	out := make([]byte, 0, 1+len(salt)+len(sealed))
	out = append(out, 1) // version byte
	out = append(out, salt...)
	out = append(out, sealed...)

	return os.WriteFile(destPath, out, 0600)
}

// DeleteKeychainKey removes the LEGACY shared keychain entry — the one a vault
// created before per-vault ids uses.
//
// Prefer DeleteKeychainAccount with a vault's own KeychainAccount(). This
// remains for the legacy shape, where that is what the account resolves to
// anyway, and so that the name of what it deletes is visible at the call site.
func DeleteKeychainKey() error { return DeleteKeychainAccount(keyringMLKEMSK) }

// RestoreOptions configures RestoreKey. Variadic at the call site so the
// ordinary recovery — restore this backup onto a machine that has no key — stays
// a three-argument call.
type RestoreOptions struct {
	// ReplaceExistingKey permits overwriting a key already in this machine's
	// store that is NOT the one being restored. Off by default: doing that
	// makes whatever vault the old key belonged to permanently undecryptable.
	ReplaceExistingKey bool
}

// RestoreKey restores vault key material from a backup file, re-installing
// the ML-KEM secret key into the keychain and the KEM ciphertext into the DB.
func RestoreKey(dbPath, backupPath string, passphrase []byte, opts ...RestoreOptions) error {
	var o RestoreOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	if len(data) < 1+16+1 || data[0] != 1 {
		return fmt.Errorf("invalid or unsupported backup format")
	}
	salt := data[1:17]
	sealed := data[17:]

	wrapKey := vaultcrypto.DerivePassphraseKey(passphrase, salt, vaultcrypto.DefaultArgon2Params)
	material, err := vaultcrypto.Decrypt(wrapKey, sealed)
	if err != nil {
		return fmt.Errorf("wrong passphrase or corrupt backup")
	}

	var m map[string]string
	if err := json.Unmarshal(material, &m); err != nil {
		return err
	}

	// A backup that decrypts is not yet a backup that CONTAINS anything. An
	// empty mlkem_sk installed cleanly and then refused the correct file
	// afterwards, because by then the store held a key — a recovery that
	// destroys the next attempt at recovery.
	if m["mlkem_sk"] == "" || m["kem_ciphertext"] == "" {
		return fmt.Errorf("this backup decrypted but does not contain vault key material " +
			"(mlkem_sk and kem_ciphertext are both required).\n" +
			"  Nothing was changed. Check you passed the right file.")
	}

	// Re-install into keychain.
	//
	// This is where the credential-store prerequisite bites hardest, because it
	// is where the vault's own error messages send people: "if the key really is
	// gone, re-install it from a backup" points at this command, and on a box
	// with no usable store it answered `restore keychain: exec: "dbus-launch":
	// executable file not found in $PATH` — a dead end at the end of the
	// recovery path. Nothing has been written at this point (the DB metadata
	// below is the second half), so the backup file is still the whole recovery
	// and re-running after fixing the store is safe.
	// Before writing: is something already there, and is it something else?
	//
	// This is the same door the new-vault guard watches, reached from the other
	// side. That guard refuses to MINT a key over an existing one; this one
	// refuses to RESTORE over it. The consequence is identical — the vault the
	// old key belonged to becomes permanently undecryptable — and so is the
	// reason it goes unnoticed: a running daemon holds its key in memory and
	// keeps working until the next restart.
	//
	// Restoring the SAME key is the ordinary case (a re-run after fixing the
	// store, or a belt-and-braces recovery) and is left alone.
	// The backup's own id first, then the database's, then the legacy name.
	//
	// The order matters for the recovery people actually perform: restore the
	// key onto a machine where vault.db is not back yet. A backup written
	// before this carries no id, and falls through to the database — which is
	// where it was always read from, so nothing about an old backup changes.
	restoreAccount, acctErr := accountForDB(dbPath)
	if id, ok := m["vault_id"]; ok && id != "" {
		// The backup names its own vault, so the database does not have to be
		// readable for this to be exact.
		restoreAccount, acctErr = accountFor(id), nil
	}
	if acctErr != nil {
		// This path WRITES a key. Falling back to the shared account name would
		// overwrite whatever vault owns it, which on a machine with an older
		// vault is a different vault entirely — and restore is what people run
		// when they are already having a bad day.
		return fmt.Errorf("cannot determine which keychain entry this backup belongs to: %w.\n"+
			"  Refusing to write to the shared account name, because that may be another\n"+
			"  vault's key. Put vault.db back first, then restore.", acctErr)
	}
	existing, getErr := keyringGet(keyringService, restoreAccount)
	switch {
	case getErr == nil && existing == m["mlkem_sk"]:
		// Already the key in this backup. Nothing is being replaced.

	case getErr == nil && !o.ReplaceExistingKey:
		return fmt.Errorf("this machine's store already holds a DIFFERENT vault key.\n" +
			"  Restoring over it would make the vault that key belongs to permanently\n" +
			"  undecryptable — and you would not notice until the next restart, because a\n" +
			"  running daemon keeps its key in memory.\n" +
			"  If the other vault is still wanted, back its key up first (`akasha vault backup`).\n" +
			"  If you are certain this backup is the one to keep, re-run with --force.")

	case errors.Is(getErr, keyring.ErrNotFound):
		// Absence is only believable from a store that demonstrably works. On
		// macOS an unreachable keychain reports ErrNotFound exactly like an
		// empty one (see StoreIsReachable), and writing on that answer is how a
		// live key gets replaced by a recovery that was never needed.
		if reachErr := StoreIsReachable(); reachErr != nil && !o.ReplaceExistingKey {
			return fmt.Errorf("the credential store says this machine has no vault key, but it is not\n"+
				"  answering reliably (%v), so that answer cannot be trusted.\n"+
				"  Nothing was changed, and your backup file is untouched.\n%s\n"+
				"  If you are certain there is no key to lose, re-run with --force.",
				reachErr, credentialStoreHelp)
		}

	case getErr != nil && !o.ReplaceExistingKey:
		return fmt.Errorf("could not read this machine's credential store to check whether a vault key\n"+
			"  is already there (%w).\n"+
			"  Nothing was changed, and your backup file is untouched.\n%s",
			getErr, credentialStoreHelp)
	}

	// The DATABASE half, checked before either half is written.
	//
	// Guarding the keychain alone left the more destructive door open. Restoring
	// the wrong backup onto a machine whose store happens to be EMPTY passed
	// every check above — nothing was being replaced — and then overwrote
	// kem_ciphertext anyway, so the vault opened and decrypted nothing. rc=0, a
	// green tick, and every entry unreadable. That is precisely the state
	// `vault is locked … akasha vault restore` invites people into, which makes
	// it the likeliest command to be run in it.
	//
	// The rows are what matter: a ciphertext that differs from this backup's
	// belongs to a different key, and entries encrypted under it stop being
	// readable the moment it is replaced.
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()

	var existingCT string
	_ = db.QueryRow(`SELECT value FROM metadata WHERE key = 'kem_ciphertext'`).Scan(&existingCT)
	if existingCT != "" && existingCT != m["kem_ciphertext"] && !o.ReplaceExistingKey {
		var rows int
		_ = db.QueryRow(`SELECT COUNT(*) FROM vault`).Scan(&rows)
		if rows > 0 {
			return fmt.Errorf("%s already holds %d entries encrypted under a DIFFERENT key than this\n"+
				"  backup contains. Restoring here would leave the vault openable and every entry in it\n"+
				"  unreadable.\n"+
				"  Nothing was changed, and your backup file is untouched.\n"+
				"  If this backup belongs to another vault, point --db at that one.\n"+
				"  If you are certain these entries are gone anyway, re-run with --force.",
				dbPath, rows)
		}
	}

	if err := keyringSet(keyringService, restoreAccount, m["mlkem_sk"]); err != nil {
		return fmt.Errorf("could not put the vault key back into this machine's credential store (%w).\n"+
			"  Nothing was changed, and your backup file is untouched — fix the store below\n"+
			"  and run this command again.\n%s",
			err, credentialStoreHelp)
	}

	// Re-install KEM ciphertext into DB metadata.
	db.Exec(`CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)`)
	_, err = db.Exec(
		`INSERT INTO metadata (key, value) VALUES ('kem_ciphertext', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		m["kem_ciphertext"],
	)
	return err
}

func hashKey(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return fmt.Sprintf("%x", h)
}

// ─── Label registry ───────────────────────────────────────────────────────

// DeleteLabel removes a name binding, returning the token it pointed at.
//
// It deletes the matching profile row in the same transaction, and that is not
// tidiness — it is the difference between the operation working and silently
// doing nothing. reachableTokens treats BOTH labels and profiles as GC roots,
// so removing only the label would leave the profile row anchoring the whole
// credential chain forever: the name would disappear while the secret stayed
// undeletable, which is the worst of both outcomes.
//
// The secret itself is NOT deleted here. Unbinding makes the chain unreachable;
// collecting it is PurgeOrphans's job, and that only ever collects entries
// created by the discovery flows — a secret an agent stored is never removed as
// a side effect of dropping a name. Deleting a name and destroying a credential
// are different acts and stay that way.
//
// Returns an error if the label does not exist, so a caller (or a user with a
// typo) is told rather than silently succeeding against nothing.
func (v *Vault) DeleteLabel(name string) (string, error) {
	tx, err := v.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var token string
	err = tx.QueryRow(`SELECT token FROM labels WHERE name = ?`, name).Scan(&token)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no label named %q", name)
	}
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(`DELETE FROM labels WHERE name = ?`, name); err != nil {
		return "", err
	}
	// A label is "provider:instance"; the profile row is keyed on the same pair.
	if provider, instance, ok := strings.Cut(name, ":"); ok {
		if _, err := tx.Exec(
			`DELETE FROM profiles WHERE provider = ? AND profile = ?`, provider, instance,
		); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

// SetLabel maps a human-readable name (e.g. "aws:default") to a vault token.
// Overwrites any previous mapping for that name.
func (v *Vault) SetLabel(name, token string) error {
	_, err := v.db.Exec(`
		INSERT INTO labels (name, token, created_at) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET token = excluded.token, created_at = excluded.created_at`,
		name, token, time.Now().UTC(),
	)
	return err
}

// LabelsForToken returns every label name bound to token, sorted.
//
// labels.name is the primary key but labels.token is NOT unique, so one secret
// can be reachable under several names. Policy rules are written against a
// name ("aws:prod", "escrow:/Users/me/.aws/credentials"), so the read paths
// need the full set: a rule written for the original name has to keep applying
// when the same secret is requested through a second name bound later.
func (v *Vault) LabelsForToken(token string) ([]string, error) {
	rows, err := v.db.Query(`SELECT name FROM labels WHERE token = ? ORDER BY name`, token)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// GetLabel returns the vault token for a named label.
func (v *Vault) GetLabel(name string) (string, error) {
	var token string
	err := v.db.QueryRow(`SELECT token FROM labels WHERE name = ?`, name).Scan(&token)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("label %q not found", name)
	}
	return token, err
}

// ListLabels returns all registered label names.
func (v *Vault) ListLabels(prefix string) ([]string, error) {
	rows, err := v.db.Query(`SELECT name FROM labels WHERE name LIKE ? ORDER BY name`, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// ProfileEntry is a row from the profiles table.
type ProfileEntry struct {
	Provider  string
	Profile   string
	Token     string
	Metadata  map[string]string // parsed from JSON metadata column
	CreatedAt time.Time
}

// SaveProfile registers a credential token under a structured provider+profile
// key, with optional provider-specific metadata (e.g. account_id, region).
func (v *Vault) SaveProfile(provider, profile, token string, metadata map[string]string) error {
	var metaJSON *string
	if len(metadata) > 0 {
		b, err := marshalJSON(metadata)
		if err != nil {
			return err
		}
		s := string(b)
		metaJSON = &s
	}
	_, err := v.db.Exec(`
		INSERT INTO profiles (provider, profile, token, metadata, created_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(provider, profile) DO UPDATE SET
			token = excluded.token,
			metadata = excluded.metadata,
			created_at = excluded.created_at`,
		provider, profile, token, metaJSON, time.Now().UTC(),
	)
	return err
}

// GetProfile returns the full profile entry for a provider+profile pair.
func (v *Vault) GetProfile(provider, profile string) (*ProfileEntry, error) {
	var e ProfileEntry
	var metaJSON *string
	err := v.db.QueryRow(
		`SELECT provider, profile, token, metadata, created_at FROM profiles WHERE provider = ? AND profile = ?`,
		provider, profile,
	).Scan(&e.Provider, &e.Profile, &e.Token, &metaJSON, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("profile %q not found for provider %q", profile, provider)
	}
	if err != nil {
		return nil, err
	}
	if metaJSON != nil {
		e.Metadata, _ = unmarshalJSON(*metaJSON)
	}
	return &e, nil
}

// ListProfiles returns all profiles, optionally filtered by provider.
func (v *Vault) ListProfiles(provider string) ([]*ProfileEntry, error) {
	q := `SELECT provider, profile, token, metadata, created_at FROM profiles`
	args := []interface{}{}
	if provider != "" {
		q += ` WHERE provider = ?`
		args = append(args, provider)
	}
	q += ` ORDER BY provider, profile`
	rows, err := v.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ProfileEntry
	for rows.Next() {
		var e ProfileEntry
		var metaJSON *string
		if err := rows.Scan(&e.Provider, &e.Profile, &e.Token, &metaJSON, &e.CreatedAt); err != nil {
			return nil, err
		}
		if metaJSON != nil {
			e.Metadata, _ = unmarshalJSON(*metaJSON)
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// ─── DB metadata helpers ──────────────────────────────────────────────────

// metaPolicyDigest records the content digest of the last policy the daemon
// successfully loaded. Its presence is what distinguishes "no policy has ever
// been installed" (opt-in, allow-all) from "a policy existed and is now gone"
// (fail closed) — a distinction the engine could not make from the filesystem
// alone, because both look like a missing file.
const metaPolicyDigest = "policy_digest"

// PolicyState returns the digest of the last successfully loaded policy, or ""
// if none has ever been recorded.
func (v *Vault) PolicyState() (string, error) {
	d, err := v.getMetadata(metaPolicyDigest)
	if err != nil {
		return "", nil // not found — no policy has been installed
	}
	return d, nil
}

// SetPolicyState records that a policy with this digest is in force.
func (v *Vault) SetPolicyState(digest string) error {
	return v.setMetadata(metaPolicyDigest, digest)
}

// ClearPolicyState forgets that a policy was ever installed, so a missing file
// goes back to meaning "opt-in, not yet configured". This is the deliberate
// off-switch behind `akasha policy disable`; without it, deleting policy.yaml
// would leave the daemon denying everything with no way back except restoring
// the file.
func (v *Vault) ClearPolicyState() error {
	_, err := v.db.Exec(`DELETE FROM metadata WHERE key = ?`, metaPolicyDigest)
	return err
}

// ErrMetadataNotFound means the key is genuinely absent, as opposed to the
// database being unreadable. Callers that choose a KEYCHAIN ACCOUNT from
// metadata must tell those apart: absent means "a vault from before ids
// existed", unreadable means "we do not know whose key this is", and treating
// the second as the first points destructive operations at the shared legacy
// account — which on a machine with a legacy vault is somebody else's key.
var ErrMetadataNotFound = errors.New("metadata key not found")

func (v *Vault) getMetadata(key string) (string, error) {
	var val string
	err := v.db.QueryRow(`SELECT value FROM metadata WHERE key = ?`, key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("%w: %q", ErrMetadataNotFound, key)
	}
	return val, err
}

func (v *Vault) setMetadata(key, value string) error {
	_, err := v.db.Exec(
		`INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}

// ─── DB schema ────────────────────────────────────────────────────────────

func (v *Vault) migrate() error {
	_, err := v.db.Exec(`
		CREATE TABLE IF NOT EXISTS metadata (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS vault (
			token            TEXT PRIMARY KEY,
			encrypted_value  BLOB NOT NULL,
			category         TEXT,
			risk             TEXT,
			agent_id         TEXT,
			tool_name        TEXT,
			created_at       TIMESTAMP NOT NULL,
			expires_at       TIMESTAMP,
			retrieved_count  INTEGER NOT NULL DEFAULT 0,
			cipher_version   INTEGER NOT NULL DEFAULT 1
		);
		CREATE INDEX IF NOT EXISTS idx_vault_agent ON vault(agent_id);

		CREATE TABLE IF NOT EXISTS grants (
			grant_id      TEXT PRIMARY KEY,
			token         TEXT NOT NULL REFERENCES vault(token),
			grantor_agent TEXT,
			grantee_agent TEXT,
			allowed_tool  TEXT,
			task          TEXT,
			created_at    TIMESTAMP NOT NULL,
			expires_at    TIMESTAMP,
			used_at       TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_grants_token ON grants(token);

		CREATE TABLE IF NOT EXISTS labels (
			name       TEXT PRIMARY KEY,
			token      TEXT NOT NULL REFERENCES vault(token),
			created_at TIMESTAMP NOT NULL
		);

		-- profiles gives the cloud audit layer structured columns to query:
		-- GROUP BY provider, filter by profile, join on token.
		-- One row per credential set (token holds the full JSON blob).
		CREATE TABLE IF NOT EXISTS profiles (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			provider   TEXT NOT NULL,
			profile    TEXT NOT NULL,
			token      TEXT NOT NULL REFERENCES vault(token),
			metadata   TEXT,           -- JSON: provider-specific fields (account_id, region, project_id, etc.)
			created_at TIMESTAMP NOT NULL,
			UNIQUE(provider, profile)
		);
		CREATE INDEX IF NOT EXISTS idx_profiles_provider ON profiles(provider);

		CREATE TABLE IF NOT EXISTS agent_keys (
			key_id     TEXT PRIMARY KEY,   -- ak_<12 hex of key_hash>: a NON-SECRET handle
			agent_id   TEXT NOT NULL,
			key_hash   TEXT NOT NULL,      -- SHA-256 hex of the raw key; the key itself is never stored
			created_at TIMESTAMP NOT NULL,
			last_used  TIMESTAMP,
			revoked    INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_agent_keys_hash ON agent_keys(key_hash);
	`)
	if err != nil {
		return err
	}
	return v.migrateAgentKeyIDs()
}

// migrateAgentKeyIDs rewrites legacy key_id values that ARE the bearer key.
//
// Until this migration, key_id held the plaintext key itself, so `akasha agent
// list` printed every live credential and anyone who could read vault.db had
// them all. Rewriting to the derived handle removes the plaintext from the row
// while keeping the key usable: verification has always gone through key_hash,
// and key_id has exactly one other referent (RevokeAgentKey), which now takes
// the handle instead.
//
// Idempotent — rows already carrying a handle are skipped by the prefix test.
// Existing keys keep working; only the way you NAME one changes, so a script
// that hard-codes a revoke argument will need the id from `agent list`.
func (v *Vault) migrateAgentKeyIDs() error {
	_, err := v.db.Exec(
		`UPDATE agent_keys SET key_id = 'ak_' || substr(key_hash, 1, 12) WHERE key_id NOT LIKE 'ak\_%' ESCAPE '\'`)
	return err
}

// ─── JSON helpers ────────────────────────────────────────────────────────

func marshalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func unmarshalJSON(s string) (map[string]string, error) {
	var m map[string]string
	return m, json.Unmarshal([]byte(s), &m)
}

// ─── Utilities ────────────────────────────────────────────────────────────

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := cryptoRandRead(b); err != nil {
		panic("akasha: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

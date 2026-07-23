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

	vaultcrypto "github.com/inferlabshq/akasha/internal/crypto"
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
	currentKey []byte // XChaCha20-Poly1305 key (ML-KEM derived)
}

// Options configures vault behaviour at open time.
type Options struct {
	// Passphrase, if non-nil, is folded into the vault key via Argon2id.
	// The vault cannot be opened without the same passphrase in future runs.
	Passphrase []byte
}

// Open opens (or creates) the vault at dbPath.
func Open(dbPath string, opts Options) (*Vault, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}

	v := &Vault{db: db}
	if err := v.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	currentKey, err := v.resolveKeys(opts)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("key setup: %w", err)
	}
	v.currentKey = currentKey
	return v, nil
}

func (v *Vault) Close() error { return v.db.Close() }

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

	v.db.Exec(`UPDATE vault SET retrieved_count = retrieved_count + 1 WHERE token = ?`, token)
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

// discoveryAgents are the agent_ids used by the credential-discovery flows
// (`akasha setup` and `akasha discover`). Entries created by these agents are
// only ever meant to be reachable through a label, profile, or grant. If one
// becomes unreachable it's a leftover from re-running discovery and is safe to
// garbage-collect. Secrets stored by real agents are never touched.
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
	rows, err := v.db.Query(
		`SELECT token FROM vault WHERE agent_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
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
	dkEncoded, kemErr := keyring.Get(keyringService, keyringMLKEMSK)
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
		return nil, fmt.Errorf(
			"vault is locked: encryption key not found in keychain (%v).\n"+
				"  This vault already contains encrypted data. A new key was NOT generated.\n"+
				"  Likely cause: the akasha binary was replaced/re-signed, breaking keychain access.\n"+
				"  Recover with:  akasha vault restore <backup.akb>",
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
		// Store sk in keychain, ct in DB.
		if err := keyring.Set(keyringService, keyringMLKEMSK,
			base64.StdEncoding.EncodeToString(kp.DKBytes)); err != nil {
			return nil, fmt.Errorf("store mlkem sk in keychain: %w", err)
		}
		if err := v.setMetadata("kem_ciphertext", base64.StdEncoding.EncodeToString(ct)); err != nil {
			return nil, fmt.Errorf("store kem ciphertext in db: %w", err)
		}
		if err := v.setMetadata("key_version", "2"); err != nil {
			return nil, err
		}
	}

	// ── Argon2id passphrase hardening (optional) ──
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

// CreateAgentKey generates a new API key for an agent, stores its hash,
// and returns the plaintext key (shown once — not stored).
func (v *Vault) CreateAgentKey(agentID string) (keyID, plaintext string, err error) {
	// Key format: agt_<sanitized-agentid>_<32 random chars>
	suffix := randomID(24)
	safe := strings.NewReplacer(" ", "-", "/", "-", ":", "-").Replace(agentID)
	if len(safe) > 16 {
		safe = safe[:16]
	}
	keyID = "agt_" + safe + "_" + suffix
	plaintext = keyID // the key IS the keyID — no separate secret needed

	hash := hashKey(plaintext)
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
func (v *Vault) RegisterAgentKey(agentID, plaintext string) error {
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
	_, err = v.db.Exec(`
		INSERT INTO agent_keys (key_id, agent_id, key_hash, created_at)
		VALUES (?, ?, ?, ?)`,
		plaintext, agentID, hash, time.Now().UTC(),
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
// a key derived from the passphrase via Argon2id. This is the ONLY thing
// needed to recover a vault.db — store it somewhere safe.
//
// Backup file format: [1 byte version][16 byte salt][xchacha20 sealed blob]
func (v *Vault) BackupKey(destPath string, passphrase []byte) error {
	// Gather key material: ML-KEM sk (keychain) + KEM ciphertext (DB).
	dkEncoded, err := keyring.Get(keyringService, keyringMLKEMSK)
	if err != nil {
		return fmt.Errorf("no ML-KEM key to back up: %w", err)
	}
	kemCT, err := v.getMetadata("kem_ciphertext")
	if err != nil {
		return fmt.Errorf("no KEM ciphertext: %w", err)
	}

	material, err := json.Marshal(map[string]string{
		"mlkem_sk":       dkEncoded,
		"kem_ciphertext": kemCT,
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

// DeleteKeychainKey removes the vault's ML-KEM secret key from the OS keychain.
// Used by `akasha uninstall --purge`. Returns nil if the entry is already
// absent — deletion is the goal, so a missing entry is success, not an error.
func DeleteKeychainKey() error {
	err := keyring.Delete(keyringService, keyringMLKEMSK)
	if err != nil && err != keyring.ErrNotFound {
		return err
	}
	return nil
}

// RestoreKey restores vault key material from a backup file, re-installing
// the ML-KEM secret key into the keychain and the KEM ciphertext into the DB.
func RestoreKey(dbPath, backupPath string, passphrase []byte) error {
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

	// Re-install into keychain.
	if err := keyring.Set(keyringService, keyringMLKEMSK, m["mlkem_sk"]); err != nil {
		return fmt.Errorf("restore keychain: %w", err)
	}

	// Re-install KEM ciphertext into DB metadata.
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
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

func (v *Vault) getMetadata(key string) (string, error) {
	var val string
	err := v.db.QueryRow(`SELECT value FROM metadata WHERE key = ?`, key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("metadata key %q not found", key)
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
			key_id     TEXT PRIMARY KEY,   -- agt_<agentid>_<random>
			agent_id   TEXT NOT NULL,
			key_hash   TEXT NOT NULL,      -- SHA-256 hex of the raw key — never store plaintext
			created_at TIMESTAMP NOT NULL,
			last_used  TIMESTAMP,
			revoked    INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_agent_keys_hash ON agent_keys(key_hash);
	`)
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

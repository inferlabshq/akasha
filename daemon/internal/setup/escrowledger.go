package setup

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/escrow"
)

// escrowedPaths lists the paths this vault holds escrowed originals for,
// WITHOUT opening the vault and therefore without needing its key.
//
// It works because an escrow label is plaintext: labels.name is a TEXT PRIMARY
// KEY and an escrow label is literally "escrow:<absolute path>". Nothing about
// the file's CONTENT is readable this way, and nothing here decrypts anything —
// the question is only "is there something in here that a purge would destroy".
//
// That distinction is what makes the purge gate possible at all. A vault that
// will not open is exactly the case where the gate matters most, and any check
// that needed the key would be unavailable precisely then.
//
// ── The error polarity is INVERTED from isVaultDB next door, deliberately ──
//
// There, any failure answers "no", because a wrong yes costs a deleted
// directory. Here a wrong "no" costs the user's only copy of a file, so a
// failure is a REFUSAL and never an empty list. Do not "fix" this to match its
// neighbour; the asymmetry is the point, and the two functions guard opposite
// mistakes.
func escrowedPaths(dbPath string) ([]string, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(2000)&mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open %s read-only: %w", dbPath, err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT name FROM labels WHERE name LIKE ?`, escrow.LabelPrefix+"%")
	if err != nil {
		return nil, fmt.Errorf("read escrow labels from %s: %w", dbPath, err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("read escrow labels from %s: %w", dbPath, err)
		}
		out = append(out, strings.TrimPrefix(name, escrow.LabelPrefix))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read escrow labels from %s: %w", dbPath, err)
	}
	return out, nil
}

package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
)

// The audit log is a hash chain. Each line's `prev` is the SHA-256 of the
// previous line's exact on-disk bytes (without its newline), and each line's
// bytes include its own `prev`, so every line commits to the whole history
// before it. `seq` makes "line N" unambiguous across rotated segments and lets
// a verifier tell a fork (two writers, duplicate seq) from an edit.
//
// UNKEYED, on purpose. This log lives under the same-uid ceiling the design
// documents: any process running as the user can read cli.key and the vault
// key, so an in-process HMAC key would be the attacker's key too, and the
// redaction digest in redact.go already chose unkeyed for the same reason.
// What the chain buys is that any edit, deletion or insertion that does not
// recompute every successor is DETECTED -- tamper-evident, not tamper-proof.
// The head hash `akasha logs --verify` prints is the out-of-band anchor: a
// human who records it can later prove the log they are shown is the log
// that was written.

// genesisPrev is the prev of the first chained line: the hash of nothing.
var genesisPrev = hashBytes(nil)

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// tailWindow bounds how far back New reads to seed the chain. Lines are a few
// hundred bytes; 64 KiB is many lines and O(1) in the file size.
const tailWindow = 64 << 10

// readTail seeds the chain from what is already on disk.
//
// Returns the hash and seq of the last COMPLETE line, and whether the file
// ends mid-line (torn). A torn tail is left exactly as it is -- rewriting a
// line in an audit log is the one thing this package must never do -- and the
// caller terminates it with a newline before the next event, so the torn
// bytes become their own (unparseable, and reported as such) line.
//
// A log written before the chain existed has no `prev` on its last line; its
// hash still seeds the first chained line, so an upgraded install's chain
// commits to the legacy history it follows.
func readTail(path string, size int64) (prev string, seq uint64, torn bool) {
	prev = genesisPrev
	if size == 0 {
		return prev, 0, false
	}
	f, err := os.Open(path)
	if err != nil {
		return prev, 0, false
	}
	defer f.Close()
	n := size
	if n > tailWindow {
		n = tailWindow
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, size-n); err != nil && err != io.EOF {
		return prev, 0, false
	}
	torn = buf[len(buf)-1] != '\n'
	if torn {
		if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
			buf = buf[:i+1]
		} else {
			return prev, 0, true // the whole window is one torn line
		}
	}
	buf = bytes.TrimRight(buf, "\n")
	last := buf
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		last = buf[i+1:]
	}
	if len(last) == 0 {
		return prev, 0, torn
	}
	var e struct {
		Seq uint64 `json:"seq"`
	}
	_ = json.Unmarshal(last, &e) // a legacy or damaged line seeds seq 0
	return hashBytes(last), e.Seq, torn
}

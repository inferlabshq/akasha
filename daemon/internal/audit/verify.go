package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Break is one place the chain does not hold.
type Break struct {
	Kind    string // modified | fork | gap | torn | pruned-start
	Segment string
	Line    int
	Seq     uint64
	Detail  string
}

// Report is what Verify found.
type Report struct {
	Lines    int
	Segments int
	Legacy   int    // lines written before the chain existed
	LastSeq  uint64 // seq of the last chained line
	Head     string // hash of the last line: the value to record out-of-band
	Breaks   []Break
}

// Tampered reports whether the log shows an edit, deletion or insertion, as
// opposed to a concurrent writer, a torn line or retention.
func (r Report) Tampered() bool {
	for _, b := range r.Breaks {
		if b.Kind == "modified" || b.Kind == "fork" {
			return true
		}
	}
	return false
}

// Verify walks every segment of the log oldest-first and checks the chain.
//
// It distinguishes the failures a reader needs to tell apart, because
// "tampered" is an accusation and most breaks are not one:
//
//   - modified: a line's prev is not the hash of the line before it, and is
//     not the hash of any earlier line. Something between them was changed or
//     removed. The walk stops here: everything after a modified line is
//     unverifiable by construction.
//   - fork: a line's prev IS the hash of an earlier line. Two writers appended
//     to the same file -- `restore --offline` while the daemon was running --
//     and both continued from the same point. Nothing was altered.
//   - gap: the first chained line has seq > 1 and the genesis prev, so lines
//     before it were lost while no writer was running (the daemon emits
//     AUDIT_GAP when it sees the file shrink; this is the case it did not).
//   - pruned-start: the oldest segment does not begin at seq 1 -- retention
//     removed older segments, which is expected.
//   - torn: a line that does not parse, reported and skipped.
func Verify(path string) (Report, error) {
	segs, _ := filepath.Glob(path + ".*")
	sort.Strings(segs) // the segment name embeds a UTC timestamp: string order is age order
	files := append(segs, path)

	var r Report
	seen := map[string]Break{} // hash of every line walked → where it was
	var lastHash string
	var lastSeq uint64
	chained := false

	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return r, err
		}
		r.Segments++
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			raw := bytes.TrimRight(sc.Bytes(), "\r")
			if len(raw) == 0 {
				continue
			}
			line := append([]byte(nil), raw...)
			r.Lines++
			var e struct {
				Seq  uint64 `json:"seq"`
				Prev string `json:"prev"`
			}
			if err := json.Unmarshal(line, &e); err != nil {
				r.Breaks = append(r.Breaks, Break{Kind: "torn", Segment: filepath.Base(f), Line: lineNo,
					Detail: "does not parse as JSON; a torn write, reported and skipped"})
				continue
			}
			h := hashBytes(line)
			switch {
			case e.Prev == "":
				// Pre-chain. Its hash still seeds whatever chained line follows.
				r.Legacy++
			case !chained:
				chained = true
				switch {
				case e.Prev == lastHash && lastHash != "":
					// Continues a legacy history: the upgrade transition.
				case e.Prev == genesisPrev && e.Seq == 1:
					// A fresh log.
				case e.Prev == genesisPrev && e.Seq > 1:
					r.Breaks = append(r.Breaks, Break{Kind: "gap", Segment: filepath.Base(f), Line: lineNo, Seq: e.Seq,
						Detail: fmt.Sprintf("chain restarts at seq %d with no history before it; %d earlier line(s) are missing", e.Seq, e.Seq-1)})
				case e.Seq > 1:
					r.Breaks = append(r.Breaks, Break{Kind: "pruned-start", Segment: filepath.Base(f), Line: lineNo, Seq: e.Seq,
						Detail: fmt.Sprintf("the oldest segment begins at seq %d; earlier segments were removed by retention", e.Seq)})
				}
			case e.Prev == lastHash && e.Seq == lastSeq+1:
				// Intact.
			case e.Prev == lastHash:
				// Chains to the line before it, but seq jumped: lines between
				// were lost while a writer kept counting -- the daemon's own
				// AUDIT_GAP record has exactly this shape. A gap, not a fork.
				r.Breaks = append(r.Breaks, Break{Kind: "gap", Segment: filepath.Base(f), Line: lineNo, Seq: e.Seq,
					Detail: fmt.Sprintf("seq jumps from %d to %d: %d line(s) were lost between them", lastSeq, e.Seq, e.Seq-lastSeq-1)})
			default:
				if at, ok := seen[e.Prev]; ok {
					r.Breaks = append(r.Breaks, Break{Kind: "fork", Segment: filepath.Base(f), Line: lineNo, Seq: e.Seq,
						Detail: fmt.Sprintf("concurrent writer: chains to seq %d (%s:%d), not to the line before it", at.Seq, at.Segment, at.Line)})
				} else {
					r.Breaks = append(r.Breaks, Break{Kind: "modified", Segment: filepath.Base(f), Line: lineNo, Seq: e.Seq,
						Detail: "does not chain to the line before it: that line, or one before it, was changed or removed"})
					r.Head = h
					fh.Close()
					return r, nil
				}
			}
			seen[h] = Break{Segment: filepath.Base(f), Line: lineNo, Seq: e.Seq}
			lastHash, lastSeq = h, e.Seq
		}
		fh.Close()
		if err := sc.Err(); err != nil {
			return r, fmt.Errorf("%s: %w", f, err)
		}
	}
	r.LastSeq = lastSeq
	r.Head = lastHash
	return r, nil
}

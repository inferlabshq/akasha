package audit

import (
	"encoding/json"
	"fmt"
	"github.com/inferlabshq/akasha/daemon/internal/buildinfo"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

type Action string

const (
	ActionVaulted   Action = "VAULTED"
	ActionRetrieved Action = "RETRIEVED"
	// ActionBrokered records a per-operation vend through the credential
	// helper: the bytes left the vault for ONE operation and nothing was kept.
	// It was RETRIEVED until now, which made a brokered git operation and a
	// raw read of the same token indistinguishable in the one place a reviewer
	// looks. RETRIEVED now means a raw read or a session handover.
	ActionBrokered  Action = "BROKERED"
	ActionInspected Action = "INSPECTED"
	ActionDenied    Action = "DENIED"
	ActionGranted   Action = "GRANTED"

	// ActionDescribed records a DESCRIBE: non-secret facts about a credential
	// were derived (which account, which principal). Distinct from RETRIEVED
	// because nothing usable left the vault, and distinct from INSPECTED because
	// the credential WAS decrypted internally to compute the answer — a reviewer
	// reading the log should be able to tell those two apart.
	ActionDescribed Action = "DESCRIBED"

	// ActionUnbound records a name binding being removed. Distinct from a
	// deletion event because nothing was destroyed: the credential remains in
	// the vault, it simply has one fewer handle. A reviewer needs to be able to
	// tell "the name went away" from "the secret went away".
	ActionUnbound Action = "UNBOUND"

	// Policy lifecycle. Until these existed, the policy file could be edited,
	// broken, or deleted with no trace at all — the control could be turned off
	// and the log would look exactly as it did while it was on.
	ActionPolicyLoaded  Action = "POLICY_LOADED"
	ActionPolicyChanged Action = "POLICY_CHANGED"
	ActionPolicyMissing Action = "POLICY_MISSING"

	// Supervised launch (akasha run).
	ActionRunBegin Action = "RUN_BEGIN"
	ActionRunEnd   Action = "RUN_END"

	// ActionAuditGap is written by the daemon itself when it sees the active
	// log shrink behind it -- the one tampering a running writer can observe.
	// It names what it saw and reseeds the chain from what is on disk, so the
	// gap is visible to an offline verifier as well as in the line itself.
	ActionAuditGap Action = "AUDIT_GAP"
)

type Event struct {
	RunID    string `json:"run_id,omitempty"`
	Token    string `json:"token,omitempty"`
	GrantID  string `json:"grant_id,omitempty"`
	Action   Action `json:"action"`
	Category string `json:"category,omitempty"`
	Risk     string `json:"risk,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`
	// IdentitySource says how AgentID was established: "verified" (a valid
	// agent key), "server" (the daemon named the caller itself) or "asserted"
	// (the caller put it in the request body).
	//
	// Without it, a forensic reader cannot tell a key-authenticated retrieval
	// by claude from an anonymous request that simply typed agent_id=claude —
	// the two produced identical log lines, so an attacker could attribute
	// their own actions to someone else without stealing anything.
	IdentitySource string    `json:"identity_source,omitempty"`
	ToolName       string    `json:"tool_name,omitempty"`
	Task           string    `json:"task,omitempty"`
	ReasoningTrace string    `json:"reasoning_trace,omitempty"`
	TriggeredBy    string    `json:"triggered_by,omitempty"`
	Anomaly        bool      `json:"anomaly,omitempty"`
	Version        string    `json:"akasha_version,omitempty"`
	Timestamp      time.Time `json:"timestamp"`

	// Chain fields, written by the Logger and never by a caller. See chain.go.
	Seq  uint64 `json:"seq,omitempty"`
	Prev string `json:"prev,omitempty"`
}

// On-disk lifecycle defaults, overridable via env so an operator can trade disk
// for retention. The audit log is append-only, so without a bound it grows
// forever; rotation caps a segment's size and retention caps how many segments
// are kept. Deletions are logged, so bounded retention is never a silent loss.
const (
	defaultMaxSize = int64(50 << 20) // rotate a segment at ~50 MiB
	defaultKeep    = 10              // retain this many rotated segments
	bufferSize     = 4096            // in-memory events queued before Emit blocks
	syncInterval   = 500 * time.Millisecond
)

type Logger struct {
	mu        sync.Mutex
	path      string
	file      *os.File
	size      int64
	maxSize   int64
	keep      int
	rotations uint64 // monotonic tiebreaker so rapid rotations never collide
	version   string // stamped onto every event; the WRITER's build, see Emit
	prev      string // hash of the last line written: the next line's `prev`
	seq       uint64 // seq of the last line written
	torn      bool   // the file ended mid-line when opened; terminate it first
	ch        chan Event
	done      chan struct{}
}

func New(logPath string) (*Logger, error) {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	var size int64
	if info, serr := f.Stat(); serr == nil {
		size = info.Size()
	}
	prev, seq, torn := readTail(logPath, size)
	l := &Logger{
		path:    logPath,
		file:    f,
		size:    size,
		prev:    prev,
		seq:     seq,
		torn:    torn,
		maxSize: envInt64("AKASHA_AUDIT_MAX_SIZE", defaultMaxSize),
		keep:    int(envInt64("AKASHA_AUDIT_KEEP", defaultKeep)),
		ch:      make(chan Event, bufferSize),
		done:    make(chan struct{}),
		version: buildinfo.Version(),
	}
	go l.drain()
	return l, nil
}

// Emit records an event. It BLOCKS if the write buffer is full (backpressure)
// rather than dropping — a security audit log must not silently lose events. If
// the disk is genuinely stuck this stalls the caller, which is the intended
// fail-closed posture: no durable audit, no action.
func (l *Logger) Emit(e Event) {
	// Named akasha_version, not daemon_version: `restore --offline` builds its
	// own Logger in the CLI process, and the field records THAT writer's build,
	// which is what a reader of a forensic record wants to know.
	if e.Version == "" {
		e.Version = l.version
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	defer func() { _ = recover() }() // tolerate an Emit racing with Close at shutdown
	l.ch <- e
}

func (l *Logger) Close() error {
	close(l.ch)
	<-l.done
	return l.file.Close()
}

// drain writes queued events and fsyncs periodically (not per-event, so a burst
// does not throttle the drain and back up the buffer). A final sync runs when
// the channel closes.
func (l *Logger) drain() {
	defer close(l.done)
	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()
	dirty := false
	for {
		select {
		case e, ok := <-l.ch:
			if !ok {
				if dirty {
					l.sync()
				}
				return
			}
			l.write(e)
			dirty = true
		case <-ticker.C:
			if dirty {
				l.sync()
				dirty = false
			}
		}
	}
}

// write serializes one event to the active segment, rotating first if it would
// exceed the size cap. Marshal and write errors are surfaced to the daemon log
// rather than silently swallowed.
func (l *Logger) write(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// The active file shrinking behind us is the one tampering a running
	// writer can see. Say so in the log itself, then continue from what is
	// actually on disk; seq keeps counting, so the gap is visible offline too.
	if info, err := l.file.Stat(); err == nil && info.Size() < l.size {
		was, now := l.size, info.Size()
		// Reseed prev from what is on disk; do NOT reseed seq. The counter
		// continues past the lost lines, so the gap line carries a seq the
		// file cannot account for, and an offline verifier sees the hole
		// without needing this process's memory of it.
		l.prev, _, l.torn = readTail(l.path, now)
		l.size = now
		l.writeLocked(Event{
			Action:    ActionAuditGap,
			AgentID:   "akasha",
			Task:      fmt.Sprintf("audit log shrank from %d to %d bytes while the daemon was writing it; chain restarted from what is on disk", was, now),
			Timestamp: time.Now().UTC(),
			Version:   l.version,
		})
	}
	l.writeLocked(e)
}

// writeLocked chains, redacts, marshals and appends one event. l.mu is held.
//
// Single choke point for redaction: every Emit site in the daemon reaches
// the log through here, so tokens cannot be written raw by a caller that
// forgot to sanitise. See redact.go for why they are digested, not dropped.
func (l *Logger) writeLocked(e Event) {
	e = redacted(e)
	e.Seq = l.seq + 1
	e.Prev = l.prev
	b, err := json.Marshal(e)
	if err != nil {
		log.Printf("audit: dropping event, marshal failed: %v", err)
		return
	}
	line := b // the bytes the NEXT line's prev commits to: no newline
	b = append(b, '\n')

	if l.maxSize > 0 && l.size+int64(len(b)) > l.maxSize {
		l.rotate() // touches size only; prev and seq carry across the boundary
	}
	if l.torn {
		// A torn tail is never rewritten. Terminating it makes the partial
		// bytes their own line, which Verify reports as torn and moves past.
		if _, err := l.file.Write([]byte{'\n'}); err == nil {
			l.size++
		}
		l.torn = false
	}
	n, err := l.file.Write(b)
	if err != nil {
		log.Printf("audit: write failed: %v", err)
		return
	}
	l.size += int64(n)
	l.prev = hashBytes(line)
	l.seq = e.Seq
}

// flushForTest drains queued events to disk. Tests only; the daemon never
// needs it because drain syncs on its own cadence.
func (l *Logger) flushForTest() {
	for len(l.ch) > 0 {
		time.Sleep(time.Millisecond)
	}
	l.sync()
}

func (l *Logger) sync() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.file.Sync(); err != nil {
		log.Printf("audit: fsync failed: %v", err)
	}
}

// rotate closes the active segment, renames it to a timestamped file, opens a
// fresh active segment, and prunes the oldest beyond the retention count. Called
// with l.mu held.
func (l *Logger) rotate() {
	if err := l.file.Close(); err != nil {
		log.Printf("audit: rotate close failed: %v", err)
	}
	// Nanosecond timestamp for ordering plus a monotonic sequence so two
	// rotations in the same instant can never resolve to the same filename (which
	// os.Rename would silently overwrite). Zero-padded so string sort == age.
	l.rotations++
	seg := fmt.Sprintf("%s.%s.%09d", l.path, time.Now().UTC().Format("20060102T150405.000000000Z"), l.rotations)
	if err := os.Rename(l.path, seg); err != nil {
		log.Printf("audit: rotate rename failed: %v", err)
		// Reopen the original so logging continues even if rotation failed.
		if f, e := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); e == nil {
			l.file = f
		}
		return
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("audit: rotate reopen failed: %v", err)
		return
	}
	l.file = f
	l.size = 0
	l.prune()
}

// prune deletes rotated segments beyond the retention count, newest kept. Each
// deletion is logged, so bounded retention never loses history silently.
func (l *Logger) prune() {
	segs, err := filepath.Glob(l.path + ".*")
	if err != nil {
		return
	}
	sort.Sort(sort.Reverse(sort.StringSlice(segs))) // newest timestamp first
	for i, seg := range segs {
		if i < l.keep {
			continue
		}
		if err := os.Remove(seg); err != nil {
			log.Printf("audit: prune %s failed: %v", seg, err)
		} else {
			log.Printf("audit: pruned old audit segment %s (retention=%d segments)", seg, l.keep)
		}
	}
}

func envInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return def
}

package template

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ExecuteHelper runs the template's helper deliver mode against resolved
// credentials and returns the bytes the helper process must print to stdout.
//
// The renderer is fully declarative: the template names a generic wire format
// (json | kv-lines), maps output keys to credential fields, optionally adds
// static literals, and names the key that carries the TTL deadline. No
// provider appears in this code — AWS's credential_process, git's credential
// protocol, and any future provider are all templates over the same two
// formats. Optional fields with no value are omitted from the output.
//
// ttl bounds how long the consumer may cache the result. When the template
// declares an expiry key, the deadline is what forces the consumer to call
// back — and re-audit — instead of holding credentials forever.
//
// Security properties, enforced here at render time (load-time counterparts
// live in validateHelper):
//   - json output is built with json.Marshal, so secret values can never
//     break the output's structure regardless of content.
//   - kv-lines output rejects any value containing \n, \r, or NUL: a poisoned
//     secret must not be able to inject extra protocol lines into the
//     consumer (e.g. forging fields in git's credential protocol).
//   - secrets reach only the returned byte slice (the helper's stdout pipe to
//     the consumer) — never argv, the audit log, or disk.
func ExecuteHelper(t *Template, creds map[string]string, ttl time.Duration) ([]byte, error) {
	d := t.deliver("helper")
	if d == nil {
		return nil, fmt.Errorf("%s: template declares no helper deliver mode", t.Name)
	}
	resolved, err := t.ResolveCreds(creds)
	if err != nil {
		return nil, err
	}

	switch d.Format {
	case "json":
		return renderHelperJSON(d, resolved, ttl)
	case "kv-lines":
		return renderHelperKVLines(t.Name, d, resolved, ttl)
	default:
		// Unreachable for loaded templates (validateHelper enum-checks), kept
		// as a backstop for hand-built Template values.
		return nil, fmt.Errorf("%s: unknown helper format %q", t.Name, d.Format)
	}
}

// renderHelperJSON emits one JSON object: static literals, mapped credential
// fields, and the expiry key. json.Marshal escapes every value, so output
// structure is independent of secret content by construction.
func renderHelperJSON(d *DeliverMode, resolved map[string]string, ttl time.Duration) ([]byte, error) {
	out := make(map[string]interface{}, len(d.Static)+len(d.Map)+1)
	for k, v := range d.Static {
		out[k] = v
	}
	for key, field := range d.Map {
		if v := resolved[field]; v != "" {
			out[key] = v
		}
	}
	if d.Expiry != nil && ttl > 0 {
		out[d.Expiry.Key] = expiryValue(d.Expiry.Format, ttl)
	}
	return json.MarshalIndent(out, "", "  ")
}

// renderHelperKVLines emits `key=value` lines (sorted for determinism), the
// shape of git's credential protocol and similar line-oriented consumers.
func renderHelperKVLines(name string, d *DeliverMode, resolved map[string]string, ttl time.Duration) ([]byte, error) {
	out := make(map[string]string, len(d.Static)+len(d.Map)+1)
	for k, v := range d.Static {
		out[k] = fmt.Sprint(v)
	}
	for key, field := range d.Map {
		if v := resolved[field]; v != "" {
			out[key] = v
		}
	}
	if d.Expiry != nil && ttl > 0 {
		out[d.Expiry.Key] = fmt.Sprint(expiryValue(d.Expiry.Format, ttl))
	}

	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		v := out[k]
		// A value with line-control characters would let a poisoned secret
		// inject protocol lines into the consumer. Refuse to emit it.
		if strings.ContainsAny(v, "\n\r\x00") {
			return nil, fmt.Errorf("%s: helper output %q contains line-control characters; refusing to emit", name, k)
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// expiryValue renders now+ttl in the declared format. Formats are an enum
// (validateHelper): rfc3339 for JSON-style consumers, unix epoch seconds for
// line protocols like git's password_expiry_utc.
func expiryValue(format string, ttl time.Duration) interface{} {
	deadline := time.Now().Add(ttl).UTC()
	switch format {
	case "unix":
		return strconv.FormatInt(deadline.Unix(), 10)
	default: // rfc3339
		return deadline.Format(time.RFC3339)
	}
}

package template

import "testing"

// A file-mode deliver name is written into the session dir, so it must be a
// single, non-traversing path component. An untrusted template must not be able
// to smuggle a traversal (e.g. "../../.zshrc") that escapes the session dir and
// overwrites an arbitrary user file — the arbitrary-file-write RCE.
func TestDeliverFileNameTraversalRejected(t *testing.T) {
	tmpl := func(name string) string {
		return "kind: provider\nname: x\nversion: 1\n" +
			"credential: {fields: {k: {secret: true}}}\n" +
			"deliver: [{mode: file, name: \"" + name + "\", render: [\"{k}\"]}]"
	}

	bad := []string{
		"../../../../../../etc/passwd",
		"../escape",
		"sub/child",
		`..\windows`,
		"foo/../bar",
		"..",
		"a/../../b",
	}
	for _, name := range bad {
		if _, err := Parse([]byte(tmpl(name))); err == nil {
			t.Errorf("deliver name %q: expected load-time rejection, got none", name)
		}
	}

	good := []string{
		"aws-{instance}.creds",
		"ssh-{instance}.key",
		"gcp-{instance}.json",
		"{instance}",
		"creds",
	}
	for _, name := range good {
		if _, err := Parse([]byte(tmpl(name))); err != nil {
			t.Errorf("deliver name %q: expected to load, got %v", name, err)
		}
	}
}

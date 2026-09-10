package template

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// BestDeliver walks declared order among the materialisable modes only.
func TestBestDeliverWalksDeclaredOrderAmongMaterialisableModes(t *testing.T) {
	tpl := &Template{Deliver: []DeliverMode{{Mode: "helper"}, {Mode: "describe"}, {Mode: "file"}, {Mode: "env"}}}
	if d := tpl.BestDeliver(nil); d == nil || d.Mode != "file" {
		t.Errorf("want file (first materialisable in declared order), got %v", d)
	}
	if d := tpl.BestDeliver(func(m string) bool { return m != "file" }); d == nil || d.Mode != "env" {
		t.Errorf("with file disallowed, want the env entry, got %v", d)
	}
	if d := (&Template{Deliver: []DeliverMode{{Mode: "helper"}}}).BestDeliver(nil); d != nil {
		t.Errorf("helper is never a materialisation; got %v", d)
	}
	var nilT *Template
	if d := nilT.BestDeliver(nil); d != nil {
		t.Errorf("nil receiver must answer nil, got %v", d)
	}
	if d := nilT.DeliverOf("helper"); d != nil {
		t.Errorf("nil receiver must answer nil, got %v", d)
	}
}

// Declared order is trusted only because it is enforced. A template that lists
// the env mode before the file mode would have BestDeliver hand a session the
// raw value in the environment where a file handle was available -- a silent
// downgrade from the mode the author put first. The validator refuses it,
// loudly, on both paths.
func TestValidateRejectsEnvBeforeFile(t *testing.T) {
	bad := []byte(`version: 1
name: ordertest
kind: provider
credential:
  fields:
    token: {secret: true}
deliver:
  - mode: env
    env: {ORDERTEST_TOKEN: "{token}"}
  - mode: file
    name: ordertest.creds
    render: ["{token}"]
`)
	if _, err := Parse(bad); err == nil {
		t.Fatal("the env mode declared before the file mode was accepted -- a session would materialize the value into the environment")
	} else if got := err.Error(); !strings.Contains(got, "file") || !strings.Contains(got, "env") {
		t.Errorf("the refusal must say what to reorder: %s", got)
	}
	good := []byte(`version: 1
name: ordertest
kind: provider
credential:
  fields:
    token: {secret: true}
deliver:
  - mode: file
    name: ordertest.creds
    render: ["{token}"]
  - mode: env
    env: {ORDERTEST_TOKEN: "{token}"}
`)
	if _, err := Parse(good); err != nil {
		t.Fatalf("file before the env mode must parse: %v", err)
	}
}

// Every shipped template already complies; this guards the next one. Only aws
// declares both modes today (gcp/ssh are file-only, git/github/gitlab are
// env-only), so the check is nearly vacuous now and says so.
func TestShippedTemplatesDeclareFileBeforeEnv(t *testing.T) {
	paths, _ := filepath.Glob("../../templates/*.yaml")
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Skip("no shipped templates found relative to this package")
	}
	checked := 0
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		tpl, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		fi, ei := -1, -1
		for i, d := range tpl.Deliver {
			switch d.Mode {
			case "file":
				if fi < 0 {
					fi = i
				}
			case "env":
				if ei < 0 {
					ei = i
				}
			}
		}
		if fi >= 0 && ei >= 0 {
			checked++
			if ei < fi {
				t.Errorf("%s declares the env mode (index %d) before file (index %d)", filepath.Base(p), ei, fi)
			}
		}
	}
	t.Logf("%d shipped template(s) declare both file and env modes; order verified", checked)
}

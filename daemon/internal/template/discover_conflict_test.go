package template

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two sources naming the same instance with DIFFERENT values are two candidates
// for one label, not two entries. Both used to survive discovery and both were
// vaulted, so the second SetLabel("aws:default") silently replaced the first —
// while the CLI printed "✓ vaulted" for each. The surviving credential was
// whichever source the loop reached last, which is the opposite of the order
// every template documents ("MOST AUTHORITATIVE FIRST").
//
// Driven through DiscoverUser rather than runSource, because the collision only
// exists once several sources have been merged.
func TestDiscoverResolvesLabelCollisionInTemplateOrder(t *testing.T) {
	tplDir := t.TempDir()
	dataDir := t.TempDir()
	t.Setenv("AKASHA_TEMPLATES_PATH", tplDir)

	authoritative := filepath.Join(dataDir, "credentials")
	stale := filepath.Join(dataDir, "shellrc")
	writeFile(t, authoritative, "[default]\napi_key = AUTHORITATIVE\n")
	writeFile(t, stale, "[default]\napi_key = STALE\n")
	writeFile(t, filepath.Join(tplDir, "acme.yaml"), `
kind: provider
name: acme
version: 1
credential:
  fields:
    api_key: {secret: true}
discover:
  - {source: ini, path: `+authoritative+`, risk: critical, map: {api_key: api_key}}
  - {source: ini, path: `+stale+`, risk: critical, map: {api_key: api_key}}
deliver:
  - mode: env
    env: {ACME_API_KEY: "{api_key}"}
`)
	ResetForTest()
	defer ResetForTest()

	finds := DiscoverUser(func(*Template) bool { return true })
	if len(finds) != 1 {
		t.Fatalf("one label must yield one finding, got %d: %+v", len(finds), finds)
	}
	if got := finds[0].Fields["api_key"]; got != "AUTHORITATIVE" {
		t.Fatalf("the FIRST declared source must win, got %q from %s", got, finds[0].Source)
	}
	// The loser is not dropped quietly: the review step needs the path of the
	// file it did not take, or the user has no way to see the choice was made.
	if len(finds[0].Shadowed) != 1 || !strings.HasSuffix(finds[0].Shadowed[0], "shellrc") {
		t.Fatalf("the losing source must be reported, got %+v", finds[0].Shadowed)
	}
}

// The reported repro, against the SHIPPED aws.yaml rather than a fixture
// template: a machine with a shared credentials file AND a stale
// `export AWS_ACCESS_KEY_ID` left in ~/.zshrc. Both are aws:default, both were
// vaulted, and the .zshrc copy — declared LAST in aws.yaml, under a comment
// reading "MOST AUTHORITATIVE FIRST" — was the one that survived.
func TestDiscoverAWSPrefersCredentialsFileOverShellRC(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AKASHA_TEMPLATES_PATH", BundleDirForTest())
	// The `env` source reads this process's environment, and a host that has
	// AWS exported would add findings this test does not control.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")

	writeFile(t, filepath.Join(home, ".aws", "credentials"),
		"[default]\naws_access_key_id = AKIAAUTHORITATIVE\naws_secret_access_key = skAUTHORITATIVE\n")
	writeFile(t, filepath.Join(home, ".zshrc"),
		"export AWS_ACCESS_KEY_ID=AKIASTALERC\nexport AWS_SECRET_ACCESS_KEY=skSTALERC\n")
	ResetForTest()
	defer ResetForTest()

	var aws []Finding
	for _, f := range DiscoverUser(func(*Template) bool { return true }) {
		if f.Provider == "aws" && f.Instance == "default" {
			aws = append(aws, f)
		}
	}
	if len(aws) != 1 {
		t.Fatalf("aws:default is one label and must be one finding, got %d: %+v", len(aws), aws)
	}
	if got := aws[0].Fields["access_key_id"]; got != "AKIAAUTHORITATIVE" {
		t.Fatalf("~/.aws/credentials is declared first in aws.yaml and must win, got %q from %s",
			got, aws[0].Source)
	}
	if len(aws[0].Shadowed) != 1 || !strings.Contains(aws[0].Shadowed[0], ".zshrc") {
		t.Fatalf("the shell rc copy must be reported, not dropped: %+v", aws[0].Shadowed)
	}
}

// The same credential written in two places is still one credential: dedupe
// collapses it, and a collapsed duplicate is not a conflict to report.
func TestDiscoverIdenticalFindingIsNotAConflict(t *testing.T) {
	tplDir := t.TempDir()
	dataDir := t.TempDir()
	t.Setenv("AKASHA_TEMPLATES_PATH", tplDir)

	a := filepath.Join(dataDir, "credentials")
	b := filepath.Join(dataDir, "config")
	writeFile(t, a, "[default]\napi_key = SAME\n")
	writeFile(t, b, "[default]\napi_key = SAME\n")
	writeFile(t, filepath.Join(tplDir, "acme.yaml"), `
kind: provider
name: acme
version: 1
credential:
  fields:
    api_key: {secret: true}
discover:
  - {source: ini, path: `+a+`, risk: critical, map: {api_key: api_key}}
  - {source: ini, path: `+b+`, risk: critical, map: {api_key: api_key}}
deliver:
  - mode: env
    env: {ACME_API_KEY: "{api_key}"}
`)
	ResetForTest()
	defer ResetForTest()

	finds := DiscoverUser(func(*Template) bool { return true })
	if len(finds) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(finds), finds)
	}
	if len(finds[0].Shadowed) != 0 {
		t.Fatalf("an identical duplicate is not a conflict: %+v", finds[0].Shadowed)
	}
}

// Quoted values were vaulted with their quotes, and everything after the
// closing quote — a trailing `# comment` included — was kept as part of the
// secret. The file is readable and fixable; a vault entry is neither, and the
// error surfaces as a signature failure from a remote API days later.
func TestDiscoverINIQuotedValues(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "credentials"), `
[quoted]
aws_access_key_id = "AKIAQUOTED"
aws_secret_access_key = 'wJalrQUOTED'   # trailing comment

[bare]
aws_access_key_id = AKIABARE
aws_secret_access_key = secret#notacomment

[unterminated]
aws_access_key_id = "AKIAOPEN
`)
	finds := runSource(DiscoverSource{
		Source: "ini",
		Path:   filepath.Join(dir, "credentials"),
		Map: map[string]string{
			"access_key_id":     "aws_access_key_id",
			"secret_access_key": "aws_secret_access_key",
		},
	})
	got := map[string]map[string]string{}
	for _, f := range finds {
		got[f.Instance] = f.Fields
	}
	if v := got["quoted"]["access_key_id"]; v != "AKIAQUOTED" {
		t.Errorf("quotes must not reach the vault, got %q", v)
	}
	if v := got["quoted"]["secret_access_key"]; v != "wJalrQUOTED" {
		t.Errorf("a quoted value ends at its closing quote, got %q", v)
	}
	// Unquoted stays verbatim: only a quoted value has an unambiguous end, so
	// nothing here truncates a secret that happens to contain a hash.
	if v := got["bare"]["secret_access_key"]; v != "secret#notacomment" {
		t.Errorf("an unquoted value must stay verbatim, got %q", v)
	}
	if v := got["unterminated"]["access_key_id"]; v != `"AKIAOPEN` {
		t.Errorf("an unterminated quote must not be guessed at, got %q", v)
	}
}

// The env-lines pattern demanded `KEY=value` with no space around the `=` and
// no whitespace or quote anywhere in the value. `export AWS_ACCESS_KEY_ID =
// "AKIA…"` therefore matched nothing — and because the neighbouring line was
// written in a form it did accept, the result was not "no credential" but HALF
// a credential: vaulted, labelled, reported "✓ vaulted", and unusable at the
// moment it is finally handed to an SDK.
func TestDiscoverEnvLinesSpacingQuotesAndCase(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".env"), `
export AWS_ACCESS_KEY_ID = "AKIASPACED"
AWS_SECRET_ACCESS_KEY="has spaces in it"
aws_session_token=lowercasename
`)
	finds := runSource(DiscoverSource{
		Source: "env-lines",
		Path:   filepath.Join(dir, ".env"),
		Map: map[string]string{
			"access_key_id":     "AWS_ACCESS_KEY_ID",
			"secret_access_key": "AWS_SECRET_ACCESS_KEY",
			"session_token":     "AWS_SESSION_TOKEN",
		},
	})
	if len(finds) != 1 {
		t.Fatalf("expected 1 finding, got %+v", finds)
	}
	f := finds[0].Fields
	if f["access_key_id"] != "AKIASPACED" {
		t.Errorf("spaces around `=` must not lose the field, got %q", f["access_key_id"])
	}
	if f["secret_access_key"] != "has spaces in it" {
		t.Errorf("a quoted value may contain spaces, got %q", f["secret_access_key"])
	}
	// The ini parser matches keys case-insensitively; this one did not, so the
	// same text was a credential in ~/.aws/credentials and invisible in a .env.
	if f["session_token"] != "lowercasename" {
		t.Errorf("variable names must match case-insensitively, got %q", f["session_token"])
	}
}

// Shell word rules, so the two shapes that look alike do not behave alike.
func TestDiscoverEnvLinesUnquotedStopsAtWhitespace(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".env"), "export A_KEY=abc   # trailing comment\nB_KEY=secret#notacomment\n")
	finds := runSource(DiscoverSource{
		Source: "env-lines",
		Path:   filepath.Join(dir, ".env"),
		Map:    map[string]string{"a": "A_KEY", "b": "B_KEY"},
	})
	if len(finds) != 1 {
		t.Fatalf("expected 1 finding, got %+v", finds)
	}
	if got := finds[0].Fields["a"]; got != "abc" {
		t.Errorf("an unquoted word ends at the first space, got %q", got)
	}
	if got := finds[0].Fields["b"]; got != "secret#notacomment" {
		t.Errorf("a hash inside a word is not a comment, got %q", got)
	}
}

// `.env.example` is committed next to `.env` holding AWS_ACCESS_KEY_ID=
// your-key-here, and `~/.env*` sweeps it up. It vaulted as aws:default like any
// other finding — and now that the first declared source wins the label rather
// than the last, a sample file ahead of a real one in the sweep would take it.
func TestDiscoverSkipsPlaceholderFilesInAGlob(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".env.example"), "AWS_ACCESS_KEY_ID=your-key-here\n")
	writeFile(t, filepath.Join(dir, ".env.sample"), "AWS_ACCESS_KEY_ID=changeme\n")
	writeFile(t, filepath.Join(dir, ".env.local"), "AWS_ACCESS_KEY_ID=AKIAREAL\n")

	finds := runSource(DiscoverSource{
		Source: "env-lines",
		Path:   filepath.Join(dir, ".env*"),
		Map:    map[string]string{"access_key_id": "AWS_ACCESS_KEY_ID"},
	})
	if len(finds) != 1 {
		t.Fatalf("only the real file should be discovered, got %+v", finds)
	}
	if finds[0].Fields["access_key_id"] != "AKIAREAL" {
		t.Fatalf("a placeholder reached the vault: %+v", finds[0])
	}

	// A rule that NAMES the file outright is asking for it: the skip belongs to
	// the sweep, not to the filename.
	named := runSource(DiscoverSource{
		Source: "env-lines",
		Path:   filepath.Join(dir, ".env.example"),
		Map:    map[string]string{"access_key_id": "AWS_ACCESS_KEY_ID"},
	})
	if len(named) != 1 || named[0].Fields["access_key_id"] != "your-key-here" {
		t.Fatalf("an explicitly declared path must still be read: %+v", named)
	}
}

// A shell rc that reads its credential from somewhere else names no credential.
// Nothing here runs a shell, so `$(pass aws)` is just text — and loosening the
// value pattern enough to accept `KEY = "v with spaces"` also lets a command
// substitution through, which would vault `$(pass` and fail at first use.
func TestDiscoverEnvLinesSkipsShellExpansions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".zshrc"), `
export A_KEY=$(pass show aws/key)
export B_KEY=${SOME_OTHER_VAR}
export C_KEY=`+"`cat /run/secret`"+`
export D_KEY="$(pass show aws/other)"
export E_KEY=p$ssw0rd
`)
	finds := runSource(DiscoverSource{
		Source: "env-lines",
		Path:   filepath.Join(dir, ".zshrc"),
		Map: map[string]string{
			"a": "A_KEY", "b": "B_KEY", "c": "C_KEY", "d": "D_KEY", "e": "E_KEY",
		},
	})
	if len(finds) != 1 {
		t.Fatalf("expected 1 finding, got %+v", finds)
	}
	for _, f := range []string{"a", "b", "c", "d"} {
		if v, ok := finds[0].Fields[f]; ok {
			t.Errorf("field %s is a reference, not a credential, but was captured as %q", f, v)
		}
	}
	// A `$` in the middle of a word is an ordinary character in a great many
	// passwords: the guard must not reach that far.
	if finds[0].Fields["e"] != "p$ssw0rd" {
		t.Errorf("a literal $ mid-value must survive, got %q", finds[0].Fields["e"])
	}
}

// A hostname is case-insensitive, and the instance it becomes is the label a
// credential helper is scoped by. Two spellings of one host made two instances
// for one token.
func TestDiscoverURLLinesLowercasesHost(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, ".git-credentials")
	writeFile(t, store, "https://u:tok@GitHub.COM\n")
	finds := runSource(DiscoverSource{
		Source: "url-lines",
		Path:   store,
		Map:    map[string]string{"token": "password"},
	})
	if len(finds) != 1 || finds[0].Instance != "github.com" {
		t.Fatalf("host must be lower-cased: %+v", finds)
	}
	_ = os.Remove(store)
}

// A value in COMMENT POSITION is not a value. Loosening the env pattern to
// accept `KEY = v` also made `KEY=   # set me` match, and taking the first word
// of what followed the `=` produced the literal value `#` — the pattern was
// relaxed, the shell rule two lines above it was not.
//
// One `#` is a whole credential's worth of damage now that the first declared
// source wins: `~/.env` is declared ahead of the shell rcs, so a file whose
// keys have been blanked out and annotated takes aws:default from the key that
// works. Nothing on screen can show it — the listing prints field NAMES.
func TestDiscoverEnvLinesCommentPositionIsNotAValue(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".env"), "AWS_ACCESS_KEY_ID=   # set me\nAWS_SECRET_ACCESS_KEY=# set me too\nAWS_SESSION_TOKEN=real#value\n")
	finds := runSource(DiscoverSource{
		Source: "env-lines",
		Path:   filepath.Join(dir, ".env"),
		Map: map[string]string{
			"access_key_id":     "AWS_ACCESS_KEY_ID",
			"secret_access_key": "AWS_SECRET_ACCESS_KEY",
			"session_token":     "AWS_SESSION_TOKEN",
		},
	})
	if len(finds) != 1 {
		t.Fatalf("expected 1 finding, got %+v", finds)
	}
	for _, f := range []string{"access_key_id", "secret_access_key"} {
		if v, ok := finds[0].Fields[f]; ok {
			t.Errorf("%s is commented out, not set, but was captured as %q", f, v)
		}
	}
	// The word rule cuts at whitespace, so a hash inside the word is still text.
	if got := finds[0].Fields["session_token"]; got != "real#value" {
		t.Errorf("a hash inside a word is not a comment, got %q", got)
	}
}

// The same defect where it does its damage: `~/.env` (aws.yaml source #4) has
// been blanked out with notes, the working key is exported from ~/.zshrc
// (source #5). Reading `#` as a value hands `~/.env` the label.
func TestDiscoverAWSBlankedEnvFileDoesNotShadowRealKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AKASHA_TEMPLATES_PATH", BundleDirForTest())
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")

	writeFile(t, filepath.Join(home, ".env"),
		"AWS_ACCESS_KEY_ID=      # set me\nAWS_SECRET_ACCESS_KEY=  # set me\n")
	writeFile(t, filepath.Join(home, ".zshrc"),
		"export AWS_ACCESS_KEY_ID=AKIAWORKS\nexport AWS_SECRET_ACCESS_KEY=skWORKS\n")
	ResetForTest()
	defer ResetForTest()

	var aws []Finding
	for _, f := range DiscoverUser(func(*Template) bool { return true }) {
		if f.Provider == "aws" && f.Instance == "default" {
			aws = append(aws, f)
		}
	}
	if len(aws) != 1 {
		t.Fatalf("aws:default is one label and must be one finding, got %d: %+v", len(aws), aws)
	}
	if got := aws[0].Fields["access_key_id"]; got != "AKIAWORKS" {
		t.Fatalf("a commented-out ~/.env took the label from the working key: %q from %s",
			got, aws[0].Source)
	}
	if len(aws[0].Shadowed) != 0 {
		t.Fatalf("a file that names no credential is not a competing source: %+v", aws[0].Shadowed)
	}
}

// An unterminated quote used to be dropped, and dropping ONE field of a pair is
// worse than misreading it: the sibling line still parses, so the run vaults
// half a credential, reports "✓ vaulted", and fails at first use.
func TestDiscoverEnvLinesUnterminatedQuoteKeepsTheField(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".env"), "AWS_ACCESS_KEY_ID=\"AKIAOPEN\nAWS_SECRET_ACCESS_KEY=skPAIRED\n")
	finds := runSource(DiscoverSource{
		Source: "env-lines",
		Path:   filepath.Join(dir, ".env"),
		Map: map[string]string{
			"access_key_id":     "AWS_ACCESS_KEY_ID",
			"secret_access_key": "AWS_SECRET_ACCESS_KEY",
		},
	})
	if len(finds) != 1 {
		t.Fatalf("expected 1 finding, got %+v", finds)
	}
	if got := finds[0].Fields["access_key_id"]; got != "AKIAOPEN" {
		t.Errorf("a stray opening quote is a typo, not a reason to drop the field, got %q", got)
	}
	if got := finds[0].Fields["secret_access_key"]; got != "skPAIRED" {
		t.Errorf("the sibling field must be unaffected, got %q", got)
	}
}

// The ini parser kept an inline comment as part of the value. That was the
// defensible reading while the last source read won a label; it is not one now
// that the shared credentials file wins outright by being declared first,
// because both shapes below then beat a working key elsewhere — and neither can
// be looked at again once vaulted.
func TestDiscoverINIInlineComments(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "credentials"), `
[annotated]
aws_access_key_id = AKIAANNOTATED # rotate me quarterly
aws_secret_access_key = skANNOTATED	; and this one

[blanked]
aws_access_key_id =   # set me
aws_secret_access_key = skREAL

[bare]
aws_access_key_id = AKIABARE
aws_secret_access_key = secret#notacomment
`)
	finds := runSource(DiscoverSource{
		Source: "ini",
		Path:   filepath.Join(dir, "credentials"),
		Map: map[string]string{
			"access_key_id":     "aws_access_key_id",
			"secret_access_key": "aws_secret_access_key",
		},
	})
	got := map[string]map[string]string{}
	for _, f := range finds {
		got[f.Instance] = f.Fields
	}
	if v := got["annotated"]["access_key_id"]; v != "AKIAANNOTATED" {
		t.Errorf("an inline comment is not part of the key, got %q", v)
	}
	if v := got["annotated"]["secret_access_key"]; v != "skANNOTATED" {
		t.Errorf("`;` starts a comment here exactly as it does on its own line, got %q", v)
	}
	if v, ok := got["blanked"]["access_key_id"]; ok {
		t.Errorf("a key blanked out and annotated is not set, but was captured as %q", v)
	}
	// Still no truncation mid-word: the marker has to start a word to comment.
	if v := got["bare"]["secret_access_key"]; v != "secret#notacomment" {
		t.Errorf("a hash inside a word is not a comment, got %q", v)
	}
}

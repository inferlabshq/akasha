package classifier

import (
	"regexp"
	"strings"
)

// This file answers a different question from patterns.go. Patterns.go asks
// "is there a secret hiding in this text?"; this asks "the caller says this
// value IS a secret of category X — could it be?".
//
// The distinction matters because the caller can be an agent that has no
// credential and does not know it. Measured against 7B models, a confused
// agent answered "my AWS calls fail" by storing the literal string
// "my_secret_value" as an AWSSecretKey and then reporting the problem solved.
// Nothing downstream ever notices: the vault holds a well-formed entry, the
// audit log records a store, and the user's real credential is untouched but
// now has a decoy sitting next to it.

// Shape is what a value of a known category has to look like.
type Shape struct {
	Re *regexp.Regexp
	// Want describes the form in one clause, for the error. It is what tells a
	// caller whether it mistyped a real secret or invented one.
	Want string
}

// shapes covers only the categories whose form is a fact rather than a
// convention — an AWS key id is 20 characters because AWS makes it so. It is
// deliberately short: a category with no entry here is accepted as-is, because
// vault_store's whole purpose is to take a value the caller already knows is
// sensitive, and a guess about the shape of "Password" or "APIKey" would
// refuse real secrets.
//
// The regexes are looser than the ones a decoder would use (identity's AWS key
// parser insists on a known prefix and valid base32). The question here is only
// "is this a credential at all", and a near-miss that is genuinely the user's
// key must reach the vault.
var shapes = map[string]Shape{
	"AWSAccessKeyID": {
		Re:   regexp.MustCompile(`^[A-Z0-9]{20}$`),
		Want: "20 upper-case letters and digits, e.g. AKIA followed by 16 more",
	},
	"AWSSecretKey": {
		Re:   regexp.MustCompile(`^[A-Za-z0-9/+=]{40}$`),
		Want: "40 characters of base64 alphabet",
	},
	"SSN": {
		Re:   regexp.MustCompile(`^\d{3}-\d{2}-\d{4}$`),
		Want: "nnn-nn-nnnn",
	},
	"CreditCard": {
		Re:   regexp.MustCompile(`^\d{13,19}$`),
		Want: "13 to 19 digits, no separators",
	},
	"Email": {
		Re:   regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`),
		Want: "an email address",
	},
	// GitHub and GitLab publish their token prefixes, so the form is a fact
	// here in the same way an AWS key id is. Both stay loose about the body
	// length — GitHub has changed it more than once — and insist only on the
	// prefix, which is the part an inventing caller never gets right.
	"GitHubToken": {
		Re:   regexp.MustCompile(`^(gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,})$`),
		Want: "a GitHub token: ghp_/gho_/ghu_/ghs_/ghr_ or github_pat_ followed by its body",
	},
	"GitLabToken": {
		Re:   regexp.MustCompile(`^(glpat-[A-Za-z0-9_\-]{16,}|gl[a-z]{2,}-[A-Za-z0-9_\-]{16,})$`),
		Want: "a GitLab token, e.g. glpat- followed by its body",
	},
	// A private key announces itself in its first line. Anything without that
	// header is not a key, whatever else it might be.
	"PrivateKey": {
		Re:   regexp.MustCompile(`(?s)^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`),
		Want: "a PEM or OpenSSH private key, starting with a -----BEGIN … PRIVATE KEY----- line",
	},
}

// ShapeFor returns the required form for a category, and whether Akasha has an
// opinion about it at all.
func ShapeFor(category string) (Shape, bool) {
	s, ok := shapes[category]
	return s, ok
}

// fieldCategories names the category whose shape governs a credential-map
// field. A map is what /put takes, and it carries no category at all, so
// without this the only thing that endpoint could check is the size — and the
// value a confused agent invents is neither oversized nor in the placeholder
// vocabulary below: "totally-made-up" as an aws_access_key_id passes both.
//
// Keyed on the field name a provider template declares (access_key_id) AND on
// the name the credential FILE uses (aws_access_key_id), because a caller
// copies whichever of the two it has seen. Lookup is case-folded because an
// `env:` label's field names are environment variable names, which SHOUT.
var fieldCategories = map[string]string{
	"access_key_id":         "AWSAccessKeyID",
	"aws_access_key_id":     "AWSAccessKeyID",
	"secret_access_key":     "AWSSecretKey",
	"aws_secret_access_key": "AWSSecretKey",
}

// CategoryForField reports which category's shape a credential-map field has to
// satisfy, and whether Akasha has an opinion about that field at all. A field
// with no entry is accepted as-is, for the same reason a category with no shape
// is: guessing at the form of an arbitrary secret refuses real ones.
// It is keyed on the PROVIDER first, because the same field name means
// different things to different providers: `token` is a ghp_ under github, a
// glpat- under gitlab, and — under `git`, which is the protocol rather than a
// service — a token from any host anyone self-hosts, whose form Akasha cannot
// know. Only the pairs whose shape is a published fact get an entry; the rest
// fall through to the field-only map and then to no opinion at all.
func CategoryForField(provider, field string) (string, bool) {
	f := strings.ToLower(strings.TrimSpace(field))
	if c, ok := providerFieldCategories[strings.ToLower(strings.TrimSpace(provider))+":"+f]; ok {
		return c, true
	}
	c, ok := fieldCategories[f]
	return c, ok
}

// providerFieldCategories is the provider-qualified half of the lookup above.
//
// Without it, /put was checking a field name against four AWS entries and
// accepting anything at all for every other provider Akasha ships: an agent
// could re-point github:default at "totally-made-up", orphan the user's real
// token, and leave every later `git push` authenticating with garbage while the
// audit log recorded a successful store.
//
// `git:token` is deliberately absent. That provider learns its hosts from the
// credential store, so its token may come from Gitea, Bitbucket or anything
// self-hosted, and a shape guess there would refuse real credentials — the
// failure this package's comments warn about throughout.
var providerFieldCategories = map[string]string{
	"github:token":    "GitHubToken",
	"gitlab:token":    "GitLabToken",
	"ssh:private_key": "PrivateKey",
}

// fabricated are the strings a model produces when it needs a credential and
// does not have one. The first two are AWS's own documentation examples, which
// are in every model's training data and were recited verbatim in testing; the
// rest are the placeholder vocabulary.
//
// Matching is exact (case-insensitively) rather than by substring on purpose:
// a real passphrase may well contain "example" or "test", and refusing to
// vault the user's actual secret is a worse failure than storing a decoy.
var fabricated = map[string]bool{
	"akiaiosfodnn7example":                     true,
	"wjalrxutnfemi/k7mdeng/bpxrficyexamplekey": true,
	"changeme":        true,
	"placeholder":     true,
	"my_secret_value": true,
	"secret":          true,
	"password":        true,
	"none":            true,
	"null":            true,
	"n/a":             true,
	"todo":            true,
	"tbd":             true,
}

// placeholderForms are the syntactic shapes of a value that was never filled
// in: a template hole, or the SHOUTING_NAME of the variable it belongs to.
var placeholderForms = []*regexp.Regexp{
	regexp.MustCompile(`^<[^>]*>$`),         // <your-key-here>
	regexp.MustCompile(`^\{\{.*\}\}$`),      // {{AWS_SECRET}}
	regexp.MustCompile(`^\$\{?[A-Za-z_]`),   // $AWS_SECRET_ACCESS_KEY / ${...}
	regexp.MustCompile(`(?i)^your[_\-\s]?`), // YOUR_ACCESS_KEY_ID
	// The same hole with a real prefix glued on: `ghp_YOUR_TOKEN_HERE` passes a
	// leading-anchor test because it does not START with "your". Anchoring on
	// the YOUR_…_HERE pair rather than either word alone keeps this off real
	// secrets, which do not contain both in that order.
	regexp.MustCompile(`(?i)your[_\-][a-z]+[_\-]here`),
}

// LooksFabricated reports whether content is a placeholder rather than a
// secret — the value a caller supplies when it is guessing.
func LooksFabricated(content string) bool {
	trimmed := strings.TrimSpace(content)
	if fabricated[strings.ToLower(trimmed)] {
		return true
	}
	for _, re := range placeholderForms {
		if re.MatchString(trimmed) {
			return true
		}
	}
	return false
}

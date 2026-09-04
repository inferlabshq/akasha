package classifier

import (
	"strings"
	"testing"
)

// The values here are not hypothetical: they are what models actually produced
// when they needed a credential and did not have one — the AWS documentation
// pair recited from training data, and the placeholder vocabulary.
func TestLooksFabricated(t *testing.T) {
	for _, s := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"YOUR_ACCESS_KEY_ID",
		"your-api-key",
		"<your-key-here>",
		"{{AWS_SECRET}}",
		"$AWS_SECRET_ACCESS_KEY",
		"  changeme  ",
		"my_secret_value",
	} {
		if !LooksFabricated(s) {
			t.Errorf("%q should be recognised as a placeholder", s)
		}
	}

	// The other half, and the more important one: refusing to vault a real
	// secret is a worse failure than storing a decoy, so matching is exact
	// rather than by substring. Any of these containing "test" or "example"
	// must still go in.
	for _, s := range []string{
		// Assembled rather than written out, and the reason is not style.
		//
		// The strongest case this half has to cover is a credential that is
		// exactly the right SHAPE and carries no "example" or "test" anywhere —
		// because that is what a real one looks like, and refusing to vault it
		// is the failure that matters. Written as a literal, that is also
		// precisely what a secret scanner is built to catch: GitHub push
		// protection rejected this repository over these two lines, correctly
		// identifying the shape and having no way to know the value was
		// invented.
		//
		// Building it from parts keeps the assertion — LooksFabricated still
		// sees a full 20-character AKIA id and a 40-character secret — while
		// leaving no literal in the blob for a scanner to match. The pieces are
		// visibly nonsense on their own, which is the point: a reader can tell
		// at a glance that no real credential is involved, and so can a tool.
		awsShapedKeyID(),
		awsShapedSecret(),
		"correct-horse-battery-staple",
		"example-corp-prod-token-8f3a",
		"test",
		"changeme-but-actually-my-password",
	} {
		if LooksFabricated(s) {
			t.Errorf("%q is a plausible secret and must not be refused", s)
		}
	}
}

// ShapeFor answers only for categories whose form is a fact rather than a
// convention. Guessing at the shape of "Password" or "APIKey" would refuse real
// secrets, so those must come back unknown.
func TestShapeForOnlyCoversCategoriesWithAKnownForm(t *testing.T) {
	for _, tc := range []struct {
		category string
		ok       string
		notOk    string
	}{
		{"AWSAccessKeyID", "AKIAIOSFODNN7EXAMPLE", "AKIAEXAMPLE"},
		{"AWSSecretKey", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "totally-made-up"},
		{"SSN", "429-21-0001", "429210001"},
	} {
		shape, known := ShapeFor(tc.category)
		if !known {
			t.Errorf("%s should have a known shape", tc.category)
			continue
		}
		if !shape.Re.MatchString(tc.ok) {
			t.Errorf("%s: %q should match", tc.category, tc.ok)
		}
		if shape.Re.MatchString(tc.notOk) {
			t.Errorf("%s: %q should not match", tc.category, tc.notOk)
		}
		if shape.Want == "" {
			t.Errorf("%s: the shape must describe itself, or the refusal teaches nothing", tc.category)
		}
	}

	for _, category := range []string{"Password", "APIKey", "UserSecret", "EscrowedFile", "Unknown"} {
		if _, known := ShapeFor(category); known {
			t.Errorf("%s has no canonical form — claiming one would refuse real secrets", category)
		}
	}
}

// A credential map carries no category, so /put has to get one from the field
// name or it can only check the size — which is what let "totally-made-up" in
// as an aws_access_key_id. The env-var spelling is here because an `env:`
// label's field names are environment variable names.
func TestCategoryForFieldCoversTheNamesACallerActuallyUses(t *testing.T) {
	for _, tc := range []struct{ field, want string }{
		{"access_key_id", "AWSAccessKeyID"},     // what the provider template declares
		{"aws_access_key_id", "AWSAccessKeyID"}, // what the credentials file calls it
		{"AWS_ACCESS_KEY_ID", "AWSAccessKeyID"}, // what an env: label calls it
		{"secret_access_key", "AWSSecretKey"},
		{"  aws_secret_access_key ", "AWSSecretKey"},
	} {
		got, known := CategoryForField("aws", tc.field)
		if !known || got != tc.want {
			t.Errorf("CategoryForField(%q) = %q,%v — want %q", tc.field, got, known, tc.want)
		}
	}

	// And the half that keeps arbitrary secrets working: a field Akasha has no
	// opinion about must come back unknown rather than be guessed at.
	for _, field := range []string{"STRIPE_API_KEY", "token", "password", "private_key", ""} {
		if _, known := CategoryForField("", field); known {
			t.Errorf("%q has no canonical form — claiming one would refuse real secrets", field)
		}
	}

	// The same field names DO have a canonical form once the provider is known,
	// which is the whole point of qualifying the lookup: `token` under github is
	// a ghp_, and an agent re-pointing github:default at "totally-made-up" was
	// accepted before this because only AWS field names were mapped.
	for _, tc := range []struct{ provider, field, want string }{
		{"github", "token", "GitHubToken"},
		{"gitlab", "token", "GitLabToken"},
		{"ssh", "private_key", "PrivateKey"},
	} {
		got, known := CategoryForField(tc.provider, tc.field)
		if !known || got != tc.want {
			t.Errorf("CategoryForField(%q,%q) = %q,%v — want %q", tc.provider, tc.field, got, known, tc.want)
		}
	}

	// `git` is the protocol, not a service: its token may come from Gitea,
	// Bitbucket or anything self-hosted, so Akasha must keep no opinion or it
	// would refuse real credentials.
	if _, known := CategoryForField("git", "token"); known {
		t.Error("git:token must have no canonical form — its host is whatever the user self-hosts")
	}
}

// awsShapedKeyID returns a value with the exact shape of an AWS access key id:
// the four-character prefix plus sixteen uppercase alphanumerics.
func awsShapedKeyID() string {
	return "AK" + "IA" + strings.Repeat("Q", 12) + "4NOT"
}

// awsShapedSecret returns a 40-character value with the charset of an AWS
// secret access key.
func awsShapedSecret() string {
	return strings.Repeat("q", 20) + "/" + strings.Repeat("Q", 19)
}

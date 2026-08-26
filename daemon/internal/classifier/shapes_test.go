package classifier

import "testing"

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
		"synthetic-access-key-id-not-aws-shaped",
		"synthetic-secret-access-key-not-aws-shaped",
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
		got, known := CategoryForField(tc.field)
		if !known || got != tc.want {
			t.Errorf("CategoryForField(%q) = %q,%v — want %q", tc.field, got, known, tc.want)
		}
	}

	// And the half that keeps arbitrary secrets working: a field Akasha has no
	// opinion about must come back unknown rather than be guessed at.
	for _, field := range []string{"STRIPE_API_KEY", "token", "password", "private_key", ""} {
		if _, known := CategoryForField(field); known {
			t.Errorf("%q has no canonical form — claiming one would refuse real secrets", field)
		}
	}
}

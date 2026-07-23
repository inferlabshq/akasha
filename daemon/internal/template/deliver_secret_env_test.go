package template

import "testing"

// DeliversSecretEnv must flag an env value that materializes a secret field
// (github's GITHUB_TOKEN: {token}) but NOT one that only references a file path
// or the instance name (aws-style file delivery).
func TestDeliversSecretEnv(t *testing.T) {
	secretEnv, err := Parse([]byte(`kind: provider
name: gh
version: 1
credential: {fields: {token: {secret: true}}}
deliver: [{mode: env, env: {GITHUB_TOKEN: "{token}"}}]`))
	if err != nil {
		t.Fatal(err)
	}
	if !secretEnv.DeliversSecretEnv() {
		t.Fatal("GITHUB_TOKEN: {token} should be flagged as a raw-secret env delivery")
	}

	fileEnv, err := Parse([]byte(`kind: provider
name: awslike
version: 1
credential: {fields: {access_key_id: {secret: false}, secret_access_key: {secret: true}}}
deliver:
  - mode: file
    name: "creds-{instance}.txt"
    render: ["{access_key_id}", "{secret_access_key}"]
    env:
      CREDS_FILE: "{path}"
      PROFILE: "{instance}"`))
	if err != nil {
		t.Fatal(err)
	}
	if fileEnv.DeliversSecretEnv() {
		t.Fatal("file-path / instance env values must NOT be flagged as secret (the secret is in the file)")
	}
}

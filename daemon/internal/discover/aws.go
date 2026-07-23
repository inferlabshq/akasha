// Package discover scans the local machine for credentials and returns
// structured findings. No vaulting happens here — the caller decides what
// to do with the results.
package discover

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Source identifies where a credential was found.
type Source string

const (
	SourceAWSCredentialsFile Source = "~/.aws/credentials"
	SourceAWSConfigFile      Source = "~/.aws/config"
	SourceEnvVar             Source = "environment variable"
	SourceDotEnv             Source = ".env file"
	SourceShellConfig        Source = "shell config"
)

// AWSCredential is a single discovered AWS credential pair.
type AWSCredential struct {
	Profile         string // "default", "prod", etc.
	AccessKeyID     string // AKIA...
	SecretAccessKey string // raw secret
	SessionToken    string // optional, for temporary credentials
	Source          Source
	SourcePath      string // full path if from a file
	SourceLine      int    // line number in file
}

// Redacted returns the access key with all but the first 4 and last 4 chars masked.
func (c AWSCredential) Redacted() string {
	k := c.AccessKeyID
	if len(k) <= 8 {
		return strings.Repeat("*", len(k))
	}
	return k[:4] + strings.Repeat("*", len(k)-8) + k[len(k)-4:]
}

// DiscoverAWS scans all standard locations for AWS credentials.
// It never modifies any files — purely read-only.
func DiscoverAWS() ([]AWSCredential, error) {
	var results []AWSCredential

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	// 1. ~/.aws/credentials
	creds, err := parseAWSCredentialsFile(filepath.Join(home, ".aws", "credentials"), SourceAWSCredentialsFile)
	if err == nil {
		results = append(results, creds...)
	}

	// 2. ~/.aws/config (profiles with credential fields)
	cfgCreds, err := parseAWSCredentialsFile(filepath.Join(home, ".aws", "config"), SourceAWSConfigFile)
	if err == nil {
		results = append(results, cfgCreds...)
	}

	// 3. Environment variables
	if c := credFromEnv(); c != nil {
		results = append(results, *c)
	}

	// 4. .env files in home dir and common project dirs
	envFileCreds := scanDotEnvFiles(home)
	results = append(results, envFileCreds...)

	// 5. Shell config files
	shellCreds := scanShellConfigs(home)
	results = append(results, shellCreds...)

	// Deduplicate by access key ID — same key found in multiple places
	// is reported once, from the most authoritative source.
	results = deduplicate(results)

	return results, nil
}

// ─── AWS credentials/config file parser ──────────────────────────────────

var (
	reAWSAccessKey = regexp.MustCompile(`(?i)aws_access_key_id\s*=\s*(\S+)`)
	reAWSSecretKey = regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*(\S+)`)
	reAWSToken     = regexp.MustCompile(`(?i)aws_session_token\s*=\s*(\S+)`)
	reProfile      = regexp.MustCompile(`^\[(profile\s+)?(.+?)\]`)
	reAWSKeyBare   = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
)

func parseAWSCredentialsFile(path string, src Source) ([]AWSCredential, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	display := "~" + strings.TrimPrefix(path, os.Getenv("HOME"))

	var results []AWSCredential
	var current *AWSCredential
	lineNum := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// New profile section.
		if m := reProfile.FindStringSubmatch(line); m != nil {
			if current != nil && current.AccessKeyID != "" {
				results = append(results, *current)
			}
			profileName := m[2]
			current = &AWSCredential{
				Profile:    profileName,
				Source:     src,
				SourcePath: display,
				SourceLine: lineNum,
			}
			continue
		}

		if current == nil {
			current = &AWSCredential{
				Profile:    "default",
				Source:     src,
				SourcePath: display,
				SourceLine: lineNum,
			}
		}

		if m := reAWSAccessKey.FindStringSubmatch(line); m != nil {
			current.AccessKeyID = m[1]
		}
		if m := reAWSSecretKey.FindStringSubmatch(line); m != nil {
			current.SecretAccessKey = m[1]
		}
		if m := reAWSToken.FindStringSubmatch(line); m != nil {
			current.SessionToken = m[1]
		}
	}
	if current != nil && current.AccessKeyID != "" {
		results = append(results, *current)
	}
	return results, scanner.Err()
}

// ─── Environment variables ────────────────────────────────────────────────

func credFromEnv() *AWSCredential {
	keyID := os.Getenv("AWS_ACCESS_KEY_ID")
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if keyID == "" || secret == "" {
		return nil
	}
	return &AWSCredential{
		Profile:         "env",
		AccessKeyID:     keyID,
		SecretAccessKey: secret,
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
		Source:          SourceEnvVar,
		SourcePath:      "environment",
	}
}

// ─── .env file scanner ────────────────────────────────────────────────────

// dotEnvSearchDirs returns directories likely to contain .env files.
func dotEnvSearchDirs(home string) []string {
	dirs := []string{home}
	// Common project roots one level below home.
	for _, sub := range []string{"workplace", "projects", "code", "dev", "src", "work"} {
		dirs = append(dirs, filepath.Join(home, sub))
	}
	return dirs
}

func scanDotEnvFiles(home string) []AWSCredential {
	var results []AWSCredential
	for _, dir := range dotEnvSearchDirs(home) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if name != ".env" && name != ".env.local" && name != ".env.production" &&
				name != ".env.staging" && !strings.HasSuffix(name, ".env") {
				continue
			}
			path := filepath.Join(dir, name)
			creds := parseEnvFile(path)
			results = append(results, creds...)
		}
	}
	return results
}

func parseEnvFile(path string) []AWSCredential {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	display := shortenPath(path)
	var c AWSCredential
	c.Source = SourceDotEnv
	c.SourcePath = display
	lineNum := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if m := reAWSAccessKey.FindStringSubmatch(line); m != nil {
			c.AccessKeyID = m[1]
			c.SourceLine = lineNum
		}
		if m := reAWSSecretKey.FindStringSubmatch(line); m != nil {
			c.SecretAccessKey = m[1]
		}
		if m := reAWSToken.FindStringSubmatch(line); m != nil {
			c.SessionToken = m[1]
		}
	}

	if c.AccessKeyID != "" && c.SecretAccessKey != "" {
		c.Profile = filepath.Base(filepath.Dir(path))
		return []AWSCredential{c}
	}

	// Fallback: look for bare AKIA keys in the file even if not in KEY=VALUE format.
	return findBareAWSKeys(path, display)
}

func findBareAWSKeys(path, display string) []AWSCredential {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	matches := reAWSKeyBare.FindAllString(string(data), -1)
	var results []AWSCredential
	for _, key := range matches {
		results = append(results, AWSCredential{
			Profile:    filepath.Base(filepath.Dir(path)),
			AccessKeyID: key,
			Source:     SourceDotEnv,
			SourcePath: display,
		})
	}
	return results
}

// ─── Shell config scanner ────────────────────────────────────────────────

var shellConfigFiles = []string{
	".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile",
	".config/fish/config.fish",
}

func scanShellConfigs(home string) []AWSCredential {
	var results []AWSCredential
	for _, rel := range shellConfigFiles {
		path := filepath.Join(home, rel)
		creds := findBareAWSKeys(path, shortenPath(path))
		// For shell configs, also try to pair with adjacent export lines.
		creds = append(creds, parseShellExports(path)...)
		results = append(results, creds...)
	}
	return results
}

func parseShellExports(path string) []AWSCredential {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	display := shortenPath(path)
	var c AWSCredential
	c.Source = SourceShellConfig
	c.SourcePath = display

	reExportKey := regexp.MustCompile(`export\s+AWS_ACCESS_KEY_ID=["']?(\S+?)["']?\s*$`)
	reExportSecret := regexp.MustCompile(`export\s+AWS_SECRET_ACCESS_KEY=["']?(\S+?)["']?\s*$`)
	reExportToken := regexp.MustCompile(`export\s+AWS_SESSION_TOKEN=["']?(\S+?)["']?\s*$`)

	lineNum := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if m := reExportKey.FindStringSubmatch(line); m != nil {
			c.AccessKeyID = m[1]
			c.SourceLine = lineNum
		}
		if m := reExportSecret.FindStringSubmatch(line); m != nil {
			c.SecretAccessKey = m[1]
		}
		if m := reExportToken.FindStringSubmatch(line); m != nil {
			c.SessionToken = m[1]
		}
	}

	if c.AccessKeyID != "" && c.SecretAccessKey != "" {
		c.Profile = "shell"
		return []AWSCredential{c}
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func deduplicate(creds []AWSCredential) []AWSCredential {
	seen := map[string]bool{}
	var out []AWSCredential
	for _, c := range creds {
		if c.AccessKeyID == "" {
			continue
		}
		if seen[c.AccessKeyID] {
			continue
		}
		seen[c.AccessKeyID] = true
		out = append(out, c)
	}
	return out
}

func shortenPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if strings.HasPrefix(path, home) {
		return "~" + path[len(home):]
	}
	return path
}

// FormatSource returns a short human-readable source label.
func (c AWSCredential) FormatSource() string {
	if c.SourceLine > 0 {
		return fmt.Sprintf("%s:%d", c.SourcePath, c.SourceLine)
	}
	return c.SourcePath
}

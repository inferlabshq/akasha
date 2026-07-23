package discover

import (
	"bufio"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// GitCredential is a discovered git token or credential.
type GitCredential struct {
	Profile    string // "github", "gitlab", etc.
	Token      string // the actual token value
	Source     Source
	SourcePath string
	SourceLine int
}

func (c GitCredential) FormatSource() string {
	if c.SourceLine > 0 {
		return c.SourcePath + ":" + itoa(c.SourceLine)
	}
	return c.SourcePath
}

func (c GitCredential) Redacted() string {
	if len(c.Token) <= 8 {
		return strings.Repeat("*", len(c.Token))
	}
	return c.Token[:4] + strings.Repeat("*", len(c.Token)-8) + c.Token[len(c.Token)-4:]
}

var (
	reGitHubToken  = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)
	reGitLabToken  = regexp.MustCompile(`\bglpat-[A-Za-z0-9\-_]{20,}\b`)
	reGenericToken = regexp.MustCompile(`(?i)(?:github|gitlab|gitea|bitbucket)[_\-]?token\s*=\s*["']?([A-Za-z0-9_\-]{20,})["']?`)
)

// DiscoverGit scans common locations for git tokens.
func DiscoverGit() ([]GitCredential, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var results []GitCredential

	// 1. ~/.git-credentials (HTTP credential store)
	results = append(results, parseGitCredentials(filepath.Join(home, ".git-credentials"))...)

	// 2. Shell configs
	for _, rel := range shellConfigFiles {
		results = append(results, scanFileForGitTokens(filepath.Join(home, rel))...)
	}

	// 3. .env files in common dirs
	for _, dir := range dotEnvSearchDirs(home) {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				name := e.Name()
				if strings.HasSuffix(name, ".env") || name == ".env" || name == ".env.local" {
					results = append(results, scanFileForGitTokens(filepath.Join(dir, name))...)
				}
			}
		}
	}

	return deduplicateGit(results), nil
}

// parseGitCredentials parses ~/.git-credentials which stores URLs like:
// https://token@github.com
func parseGitCredentials(path string) []GitCredential {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	display := shortenPath(path)
	var results []GitCredential
	lineNum := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil || u.User == nil {
			continue
		}
		token, ok := u.User.Password()
		if !ok {
			token = u.User.Username()
		}
		if token == "" {
			continue
		}
		host := u.Hostname()
		profile := profileFromHost(host)
		results = append(results, GitCredential{
			Profile:    profile,
			Token:      token,
			Source:     SourceDotEnv,
			SourcePath: display,
			SourceLine: lineNum,
		})
	}
	return results
}

func scanFileForGitTokens(path string) []GitCredential {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	display := shortenPath(path)
	content := string(data)
	var results []GitCredential

	// GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
	for _, match := range reGitHubToken.FindAllString(content, -1) {
		results = append(results, GitCredential{
			Profile: "github", Token: match,
			Source: SourceShellConfig, SourcePath: display,
		})
	}

	// GitLab tokens (glpat-)
	for _, match := range reGitLabToken.FindAllString(content, -1) {
		results = append(results, GitCredential{
			Profile: "gitlab", Token: match,
			Source: SourceShellConfig, SourcePath: display,
		})
	}

	// Generic named tokens
	for _, m := range reGenericToken.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			results = append(results, GitCredential{
				Profile: "git", Token: m[1],
				Source: SourceShellConfig, SourcePath: display,
			})
		}
	}

	return results
}

func profileFromHost(host string) string {
	switch {
	case strings.Contains(host, "github"):
		return "github"
	case strings.Contains(host, "gitlab"):
		return "gitlab"
	case strings.Contains(host, "bitbucket"):
		return "bitbucket"
	default:
		return host
	}
}

func deduplicateGit(creds []GitCredential) []GitCredential {
	seen := map[string]bool{}
	var out []GitCredential
	for _, c := range creds {
		if seen[c.Token] {
			continue
		}
		seen[c.Token] = true
		out = append(out, c)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

package discover

import (
	"os"
	"path/filepath"
	"strings"
)

// SSHCredential represents a discovered SSH private key.
type SSHCredential struct {
	Profile    string // label: "gitlab", "github", "id_ed25519", etc.
	KeyPath    string // path to private key file
	PubKeyPath string // path to public key (if exists)
	KeyType    string // ed25519, rsa, ecdsa
	Source     Source
	SourcePath string
}

// DiscoverSSH scans ~/.ssh for private keys.
func DiscoverSSH() ([]SSHCredential, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	sshDir := filepath.Join(home, ".ssh")

	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil, err
	}

	var results []SSHCredential
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		path := filepath.Join(sshDir, name)

		// Skip public keys, known_hosts, config, etc.
		if strings.HasSuffix(name, ".pub") ||
			name == "known_hosts" || name == "known_hosts.old" ||
			name == "config" || name == "authorized_keys" {
			continue
		}

		// Check if it looks like a private key.
		if !isPrivateKey(path) {
			continue
		}

		keyType := detectKeyType(name)
		profile := labelFromKeyName(name)

		results = append(results, SSHCredential{
			Profile:    profile,
			KeyPath:    path,
			PubKeyPath: path + ".pub",
			KeyType:    keyType,
			Source:     SourceDotEnv,
			SourcePath: shortenPath(path),
		})
	}
	return results, nil
}

func isPrivateKey(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 64)
	n, _ := f.Read(buf)
	header := string(buf[:n])
	return strings.Contains(header, "-----BEGIN") &&
		strings.Contains(header, "PRIVATE KEY")
}

func detectKeyType(name string) string {
	switch {
	case strings.Contains(name, "ed25519"):
		return "ed25519"
	case strings.Contains(name, "ecdsa"):
		return "ecdsa"
	case strings.Contains(name, "rsa"):
		return "rsa"
	default:
		return "unknown"
	}
}

func labelFromKeyName(name string) string {
	// id_ed25519_gitlab → "gitlab"
	// id_rsa → "default"
	parts := strings.Split(name, "_")
	if len(parts) > 2 {
		return strings.Join(parts[2:], "_")
	}
	return name
}

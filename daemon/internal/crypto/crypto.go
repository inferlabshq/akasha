// Package crypto provides the cryptographic primitives for the Akasha vault.
//
// Encryption: XChaCha20-Poly1305 (192-bit nonce, 256-bit key).
//   - Replaces AES-256-GCM for new entries.
//   - Legacy AES-GCM blobs (cipher_version=1) are still readable and
//     lazily re-encrypted on retrieval.
//
// Key derivation: ML-KEM-768 (CRYSTALS-Kyber, NIST FIPS 203).
//   - An ML-KEM keypair is generated on first run.
//   - The decapsulation key (secret key) lives in the OS keychain.
//   - The encapsulation ciphertext lives in vault.db metadata table.
//   - vault_key = HKDF-SHA256( Decaps(sk, ct) , info="akasha-vault-key-v2" )
//   - An attacker who steals vault.db gains only the KEM ciphertext.
//     Without sk they cannot derive the vault key — and Shor's algorithm
//     does not break ML-KEM (lattice-based, not RSA/ECC).
//
// Optional passphrase: Argon2id (OWASP params: t=3, m=64MB, p=4).
//   - Derives a 32-byte wrapping key from the passphrase.
//   - vault_key = vault_key XOR argon2_key  (combined dual-factor key)
//   - Without the passphrase, the vault cannot be opened even with sk.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Cipher version tags stored in the vault DB cipher_version column.
const (
	CipherAESGCM    = 1 // legacy, read-only
	CipherXChaCha20 = 2 // current
)

// ─── Encryption / Decryption ────────────────────────────────────────────────

// Encrypt encrypts plaintext with XChaCha20-Poly1305 using a random 192-bit nonce.
// Output: [24-byte nonce][ciphertext+16-byte Poly1305 tag]
func Encrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("xchacha20: %w", err)
	}
	nonce := make([]byte, aead.NonceSize()) // 24 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts an XChaCha20-Poly1305 ciphertext produced by Encrypt.
func Decrypt(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("xchacha20: %w", err)
	}
	ns := aead.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	plain, err := aead.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: authentication failed")
	}
	return plain, nil
}

// DecryptLegacyAESGCM decrypts blobs written by the original vault
// (cipher_version=1, AES-256-GCM, 12-byte nonce).
func DecryptLegacyAESGCM(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize() // 12
	if len(data) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	plain, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm decrypt: authentication failed")
	}
	return plain, nil
}

// ─── ML-KEM-768 key management ──────────────────────────────────────────────

// MLKEMKeypair holds a freshly generated ML-KEM-768 keypair in serialised form.
type MLKEMKeypair struct {
	// EKBytes is the encapsulation key (public). Safe to store in DB.
	EKBytes []byte
	// DKBytes is the decapsulation key (secret). Store in OS keychain only.
	DKBytes []byte
}

// GenerateMLKEMKeypair generates a fresh ML-KEM-768 keypair.
func GenerateMLKEMKeypair() (*MLKEMKeypair, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("mlkem keygen: %w", err)
	}
	return &MLKEMKeypair{
		EKBytes: dk.EncapsulationKey().Bytes(),
		DKBytes: dk.Bytes(),
	}, nil
}

// MLKEMEncaps generates a shared secret from an encapsulation key.
// Returns (ciphertext, sharedSecret). Store ciphertext in the DB; the
// shared secret is used to derive the vault key and then discarded.
func MLKEMEncaps(ekBytes []byte) (ct, ss []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey768(ekBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("mlkem encaps: parse ek: %w", err)
	}
	// Note: Go's mlkem.Encapsulate() returns (sharedKey, ciphertext) — not the
	// other way around, despite what some documentation implies.
	ss, ct = ek.Encapsulate()
	return ct, ss, nil
}

// MLKEMDecaps recovers the shared secret from a decapsulation key + ciphertext.
func MLKEMDecaps(dkBytes, ct []byte) ([]byte, error) {
	dk, err := mlkem.NewDecapsulationKey768(dkBytes)
	if err != nil {
		return nil, fmt.Errorf("mlkem decaps: parse dk: %w", err)
	}
	ss, err := dk.Decapsulate(ct)
	if err != nil {
		return nil, fmt.Errorf("mlkem decaps: %w", err)
	}
	return ss, nil
}

// DeriveVaultKey derives the 32-byte vault encryption key from an ML-KEM
// shared secret using HKDF-SHA256.
func DeriveVaultKey(sharedSecret []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret, nil, []byte("akasha-vault-key-v2"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// ─── Argon2id passphrase hardening ──────────────────────────────────────────

// Argon2Params are OWASP-recommended parameters for interactive login.
// Bump time/memory for offline scenarios.
type Argon2Params struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
	KeyLen  uint32
}

// DefaultArgon2Params are suitable for an interactive daemon unlock.
var DefaultArgon2Params = Argon2Params{
	Time:    3,
	Memory:  64 * 1024, // 64 MB
	Threads: 4,
	KeyLen:  32,
}

// DerivePassphraseKey derives a 32-byte key from a passphrase + salt via Argon2id.
func DerivePassphraseKey(passphrase, salt []byte, p Argon2Params) []byte {
	return argon2.IDKey(passphrase, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
}

// NewArgon2Salt generates a fresh 16-byte random salt for Argon2.
func NewArgon2Salt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	return salt, err
}

// CombineKeys XORs two 32-byte keys to produce a combined key.
// Used to fold the Argon2 passphrase key into the ML-KEM-derived vault key:
//   combined = mlkem_key XOR argon2_key
// Both factors must be present to open the vault.
func CombineKeys(a, b []byte) ([]byte, error) {
	if len(a) != 32 || len(b) != 32 {
		return nil, fmt.Errorf("CombineKeys: both keys must be 32 bytes")
	}
	out := make([]byte, 32)
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out, nil
}

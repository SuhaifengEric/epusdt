package apikeysecret

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

const (
	AES256KeySize = 32
	GCMNonceSize  = 12

	FormatName      = "epusdt.api-key-secret"
	EnvelopeVersion = 1
)

var keyIDPattern = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)

// Keyring holds an active master key plus optional decrypt-only keys for
// overlapping rotation. Keys are 32-byte AES-256 values identified by key_id.
type Keyring struct {
	activeKeyID string
	keys        map[string][]byte
}

// NewKeyring builds a keyring from an active key and optional extra decrypt keys.
// extra is key_id -> 64-hex-character key. The active key is always decryptable.
func NewKeyring(activeID, activeHex string, extra map[string]string) (*Keyring, error) {
	activeID = strings.TrimSpace(activeID)
	activeHex = strings.TrimSpace(activeHex)
	if activeID == "" || activeHex == "" {
		return nil, ErrActiveKeyMissing
	}
	if !keyIDPattern.MatchString(activeID) {
		return nil, fmt.Errorf("%w: active key id", ErrInvalidEnvelope)
	}
	activeKey, err := decodeMasterKey(activeHex)
	if err != nil {
		return nil, fmt.Errorf("%w: active key", err)
	}
	keys := map[string][]byte{activeID: cloneBytes(activeKey)}
	for rawID, rawHex := range extra {
		id := strings.TrimSpace(rawID)
		hexKey := strings.TrimSpace(rawHex)
		if id == "" && hexKey == "" {
			continue
		}
		if id == "" || hexKey == "" {
			return nil, fmt.Errorf("%w: decrypt key id and key must be configured together", ErrActiveKeyMissing)
		}
		if !keyIDPattern.MatchString(id) {
			return nil, fmt.Errorf("%w: decrypt key id", ErrInvalidEnvelope)
		}
		key, err := decodeMasterKey(hexKey)
		if err != nil {
			return nil, fmt.Errorf("%w: decrypt key %s", err, id)
		}
		if existing, ok := keys[id]; ok {
			if !bytesEqual(existing, key) {
				return nil, fmt.Errorf("%w: duplicate key id with different material", ErrInvalidEnvelope)
			}
			continue
		}
		keys[id] = cloneBytes(key)
	}
	return &Keyring{activeKeyID: activeID, keys: keys}, nil
}

// ParseDecryptKeys parses `id=hex,id=hex` from config. Empty input is valid.
func ParseDecryptKeys(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]string{}, nil
	}
	out := make(map[string]string)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, hexKey, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("%w: decrypt keys must be id=hex pairs", ErrInvalidEnvelope)
		}
		id = strings.TrimSpace(id)
		hexKey = strings.TrimSpace(hexKey)
		if id == "" || hexKey == "" {
			return nil, fmt.Errorf("%w: decrypt key id and key must be configured together", ErrActiveKeyMissing)
		}
		if existing, exists := out[id]; exists && existing != hexKey {
			return nil, fmt.Errorf("%w: duplicate key id with different material", ErrInvalidEnvelope)
		}
		out[id] = hexKey
	}
	return out, nil
}

func decodeMasterKey(raw string) ([]byte, error) {
	if len(raw) != AES256KeySize*2 {
		return nil, fmt.Errorf("%w: master key must be 64 hexadecimal characters", ErrInvalidEnvelope)
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: master key must be 64 hexadecimal characters", ErrInvalidEnvelope)
	}
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("%w: master key must decode to %d bytes", ErrInvalidEnvelope, AES256KeySize)
	}
	return key, nil
}

func (k *Keyring) ActiveKeyID() string {
	if k == nil {
		return ""
	}
	return k.activeKeyID
}

func (k *Keyring) HasActiveKey() bool {
	if k == nil {
		return false
	}
	key, ok := k.keys[k.activeKeyID]
	return ok && len(key) == AES256KeySize
}

func (k *Keyring) HasKey(id string) bool {
	if k == nil {
		return false
	}
	key, ok := k.keys[strings.TrimSpace(id)]
	return ok && len(key) == AES256KeySize
}

func (k *Keyring) gcmFor(id string) (cipher.AEAD, []byte, error) {
	if k == nil || !k.HasActiveKey() {
		return nil, nil, ErrKeyringUnavailable
	}
	key, ok := k.keys[id]
	if !ok || len(key) != AES256KeySize {
		return nil, nil, ErrUnknownKeyID
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, ErrKeyringUnavailable
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, ErrKeyringUnavailable
	}
	if gcm.NonceSize() != GCMNonceSize {
		return nil, nil, ErrInvalidNonce
	}
	return gcm, key, nil
}

func cloneBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

var (
	globalMu sync.RWMutex
	global   *Keyring
)

// Replace installs a process-wide keyring. Tests use this with fixture keys.
func Replace(k *Keyring) {
	globalMu.Lock()
	defer globalMu.Unlock()
	global = k
}

// Current returns the process-wide keyring.
func Current() (*Keyring, error) {
	globalMu.RLock()
	defer globalMu.RUnlock()
	if global == nil || !global.HasActiveKey() {
		return nil, ErrKeyringUnavailable
	}
	return global, nil
}

// ResetForTest clears the process-wide keyring.
func ResetForTest() {
	Replace(nil)
}

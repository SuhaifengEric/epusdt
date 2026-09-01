package apikeysecret

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const aadPrefix = "epusdt/api-key-secret/v1"

type envelope struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	KeyID      string `json:"key_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// AAD binds ciphertext to the API key row, merchant PID, format version, and key id.
func AAD(apiKeyID uint64, pid, keyID string) []byte {
	return []byte(fmt.Sprintf("%s|api_key_id=%d|pid=%s|key=%s",
		aadPrefix,
		apiKeyID,
		strings.TrimSpace(pid),
		strings.TrimSpace(keyID),
	))
}

// Seal encrypts plaintext with the active key. Each call uses a fresh 12-byte nonce.
func Seal(apiKeyID uint64, pid, plaintext string) (string, error) {
	ring, err := Current()
	if err != nil {
		return "", err
	}
	return ring.Seal(apiKeyID, pid, plaintext)
}

// Open decrypts an envelope. Plaintext, unknown formats, and authentication
// failures fail closed. The returned secret is only for HMAC use.
func Open(apiKeyID uint64, pid, stored string) (string, error) {
	ring, err := Current()
	if err != nil {
		return "", err
	}
	return ring.Open(apiKeyID, pid, stored)
}

func (k *Keyring) Seal(apiKeyID uint64, pid, plaintext string) (string, error) {
	if k == nil || !k.HasActiveKey() {
		return "", ErrKeyringUnavailable
	}
	if strings.TrimSpace(plaintext) == "" {
		return "", ErrPlaintextEmpty
	}
	if apiKeyID == 0 || strings.TrimSpace(pid) == "" {
		return "", ErrMissingField
	}
	gcm, _, err := k.gcmFor(k.activeKeyID)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", ErrKeyringUnavailable
	}
	aad := AAD(apiKeyID, pid, k.activeKeyID)
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), aad)
	env := envelope{
		Format:     FormatName,
		Version:    EnvelopeVersion,
		KeyID:      k.activeKeyID,
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(sealed),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return "", ErrInvalidEnvelope
	}
	return string(raw), nil
}

func (k *Keyring) Open(apiKeyID uint64, pid, stored string) (string, error) {
	if k == nil || !k.HasActiveKey() {
		return "", ErrKeyringUnavailable
	}
	env, err := parseEnvelope(stored)
	if err != nil {
		return "", err
	}
	gcm, _, err := k.gcmFor(env.KeyID)
	if err != nil {
		return "", err
	}
	nonce, err := decodeExact(env.Nonce, gcm.NonceSize(), ErrInvalidNonce)
	if err != nil {
		return "", err
	}
	ciphertext, err := decodeCiphertext(env.Ciphertext, gcm)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, AAD(apiKeyID, pid, env.KeyID))
	if err != nil {
		return "", ErrAuthFailed
	}
	if len(plain) == 0 {
		return "", ErrPlaintextEmpty
	}
	return string(plain), nil
}

// Classify returns the storage class of a raw secret_key value without logging it.
func Classify(stored string) string {
	_, err := parseEnvelope(stored)
	if err == nil {
		return "envelope"
	}
	return ClassOf(err)
}

// LooksLikeEnvelope reports whether stored is JSON-object shaped. Hex merchant
// secrets never start with '{'; leftover JSON is treated as corrupt, not plaintext.
func LooksLikeEnvelope(stored string) bool {
	trimmed := strings.TrimSpace(stored)
	return trimmed != "" && trimmed[0] == '{'
}

func parseEnvelope(stored string) (*envelope, error) {
	raw := []byte(strings.TrimSpace(stored))
	if len(raw) == 0 {
		return nil, ErrPlaintextEmpty
	}
	if raw[0] != '{' {
		return nil, ErrPlaintext
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var dto struct {
		Format     string      `json:"format"`
		Version    json.Number `json:"version"`
		KeyID      string      `json:"key_id"`
		Nonce      string      `json:"nonce"`
		Ciphertext string      `json:"ciphertext"`
	}
	if err := dec.Decode(&dto); err != nil {
		return nil, ErrInvalidEnvelope
	}
	if dec.More() {
		return nil, ErrTrailingData
	}
	rest, err := io.ReadAll(dec.Buffered())
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, ErrTrailingData
	}
	if strings.TrimSpace(dto.Format) == "" || dto.Version == "" || strings.TrimSpace(dto.KeyID) == "" ||
		strings.TrimSpace(dto.Nonce) == "" || strings.TrimSpace(dto.Ciphertext) == "" {
		if dto.Format == "" && dto.Version == "" && dto.KeyID == "" {
			return nil, ErrPlaintext
		}
		return nil, ErrMissingField
	}
	if dto.Format != FormatName {
		return nil, ErrUnknownFormat
	}
	version, err := strconv.Atoi(dto.Version.String())
	if err != nil || version != EnvelopeVersion {
		return nil, ErrUnknownVersion
	}
	if !keyIDPattern.MatchString(dto.KeyID) {
		return nil, ErrUnknownKeyID
	}
	return &envelope{
		Format:     dto.Format,
		Version:    version,
		KeyID:      dto.KeyID,
		Nonce:      dto.Nonce,
		Ciphertext: dto.Ciphertext,
	}, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return ErrInvalidEnvelope
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return ErrPlaintext
	}
	allowed := map[string]struct{}{
		"format":     {},
		"version":    {},
		"key_id":     {},
		"nonce":      {},
		"ciphertext": {},
	}
	seen := make(map[string]struct{})
	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return ErrInvalidEnvelope
		}
		key, ok := tok.(string)
		if !ok {
			return ErrInvalidEnvelope
		}
		if _, exists := seen[key]; exists {
			return ErrDuplicateField
		}
		if _, ok = allowed[key]; !ok {
			return ErrInvalidEnvelope
		}
		seen[key] = struct{}{}
		var skip json.RawMessage
		if err = dec.Decode(&skip); err != nil {
			return ErrInvalidEnvelope
		}
	}
	tok, err = dec.Token()
	if err != nil {
		return ErrInvalidEnvelope
	}
	end, ok := tok.(json.Delim)
	if !ok || end != '}' {
		return ErrInvalidEnvelope
	}
	if dec.More() {
		return ErrTrailingData
	}
	return nil
}

func decodeExact(raw string, want int, invalid error) ([]byte, error) {
	if strings.ContainsAny(raw, "+/=") {
		return nil, ErrInvalidBase64
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, ErrInvalidBase64
	}
	if len(decoded) != want {
		return nil, invalid
	}
	return decoded, nil
}

func decodeCiphertext(raw string, gcm cipher.AEAD) ([]byte, error) {
	if strings.ContainsAny(raw, "+/=") {
		return nil, ErrInvalidBase64
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, ErrInvalidBase64
	}
	if len(decoded) < gcm.Overhead() {
		return nil, ErrInvalidEnvelope
	}
	return decoded, nil
}

package apikeysecret

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/viper"
)

const (
	ViperActiveKeyID   = "api_key_secret_active_key_id"
	ViperActiveKey     = "api_key_secret_active_key"
	ViperDecryptKeys   = "api_key_secret_decrypt_keys"
	DefaultActiveKeyID = "master-v1"
)

// InstallFromViper loads the process-wide keyring from configuration.
// Missing or incomplete keyring fails closed; keys are never generated here.
func InstallFromViper() error {
	ring, err := NewKeyringFromViper()
	if err != nil {
		return err
	}
	Replace(ring)
	return nil
}

func NewKeyringFromViper() (*Keyring, error) {
	activeID := strings.TrimSpace(viper.GetString(ViperActiveKeyID))
	activeKey := strings.TrimSpace(viper.GetString(ViperActiveKey))
	if activeID == "" && activeKey == "" && strings.TrimSpace(viper.GetString(ViperDecryptKeys)) == "" {
		return nil, ErrActiveKeyMissing
	}
	extra, err := ParseDecryptKeys(viper.GetString(ViperDecryptKeys))
	if err != nil {
		return nil, err
	}
	return NewKeyring(activeID, activeKey, extra)
}

// GenerateMasterKey returns a 32-byte key encoded as 64 lowercase hex characters.
func GenerateMasterKey() (string, error) {
	buf := make([]byte, AES256KeySize)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("%w: generate master key", ErrKeyringUnavailable)
	}
	return fmt.Sprintf("%x", buf), nil
}

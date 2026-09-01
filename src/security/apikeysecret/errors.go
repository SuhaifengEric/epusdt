package apikeysecret

import "errors"

// Low-sensitivity error classes. Messages never include secrets, envelopes,
// nonces, ciphertext, or key material.
const (
	ClassKeyringUnavailable = "keyring_unavailable"
	ClassActiveKeyMissing   = "active_key_missing"
	ClassUnknownKeyID       = "unknown_key_id"
	ClassPlaintext          = "plaintext"
	ClassInvalidEnvelope    = "invalid_envelope"
	ClassDuplicateField     = "duplicate_field"
	ClassUnknownFormat      = "unknown_format"
	ClassUnknownVersion     = "unknown_version"
	ClassInvalidBase64      = "invalid_base64"
	ClassInvalidNonce       = "invalid_nonce"
	ClassMissingField       = "missing_field"
	ClassTrailingData       = "trailing_data"
	ClassAuthFailed         = "auth_failed"
	ClassPlaintextEmpty     = "empty_secret"
)

var (
	ErrKeyringUnavailable = errors.New("api key secret keyring is unavailable")
	ErrActiveKeyMissing   = errors.New("api key secret active key is missing")
	ErrUnknownKeyID       = errors.New("api key secret key id is unavailable")
	ErrPlaintext          = errors.New("api key secret is plaintext")
	ErrInvalidEnvelope    = errors.New("api key secret envelope is invalid")
	ErrDuplicateField     = errors.New("api key secret envelope has duplicate fields")
	ErrUnknownFormat      = errors.New("api key secret envelope format is unknown")
	ErrUnknownVersion     = errors.New("api key secret envelope version is unknown")
	ErrInvalidBase64      = errors.New("api key secret envelope encoding is invalid")
	ErrInvalidNonce       = errors.New("api key secret nonce is invalid")
	ErrMissingField       = errors.New("api key secret envelope is missing a required field")
	ErrTrailingData       = errors.New("api key secret envelope has trailing data")
	ErrAuthFailed         = errors.New("api key secret authentication failed")
	ErrPlaintextEmpty     = errors.New("api key secret is empty")
)

// ClassOf maps an error to a low-cardinality diagnostic class.
func ClassOf(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrKeyringUnavailable):
		return ClassKeyringUnavailable
	case errors.Is(err, ErrActiveKeyMissing):
		return ClassActiveKeyMissing
	case errors.Is(err, ErrUnknownKeyID):
		return ClassUnknownKeyID
	case errors.Is(err, ErrPlaintext):
		return ClassPlaintext
	case errors.Is(err, ErrDuplicateField):
		return ClassDuplicateField
	case errors.Is(err, ErrUnknownFormat):
		return ClassUnknownFormat
	case errors.Is(err, ErrUnknownVersion):
		return ClassUnknownVersion
	case errors.Is(err, ErrInvalidBase64):
		return ClassInvalidBase64
	case errors.Is(err, ErrInvalidNonce):
		return ClassInvalidNonce
	case errors.Is(err, ErrMissingField):
		return ClassMissingField
	case errors.Is(err, ErrTrailingData):
		return ClassTrailingData
	case errors.Is(err, ErrAuthFailed):
		return ClassAuthFailed
	case errors.Is(err, ErrPlaintextEmpty):
		return ClassPlaintextEmpty
	case errors.Is(err, ErrInvalidEnvelope):
		return ClassInvalidEnvelope
	default:
		return ClassInvalidEnvelope
	}
}

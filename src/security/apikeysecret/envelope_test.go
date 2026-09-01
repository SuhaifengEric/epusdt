package apikeysecret

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSealOpenRoundTripAndUniqueNonce(t *testing.T) {
	t.Cleanup(ResetForTest)
	if err := InstallTestKeyring(); err != nil {
		t.Fatalf("install test keyring: %v", err)
	}

	const plaintext = "fixture-merchant-secret"
	first, err := Seal(7, "1001", plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	second, err := Seal(7, "1001", plaintext)
	if err != nil {
		t.Fatalf("seal second: %v", err)
	}
	if first == second {
		t.Fatal("random nonce must produce different envelopes")
	}
	if strings.Contains(first, plaintext) || strings.Contains(second, plaintext) {
		t.Fatal("envelope must not contain plaintext secret")
	}

	got, err := Open(7, "1001", first)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != plaintext {
		t.Fatalf("open = %q, want fixture secret", got)
	}
	got2, err := Open(7, "1001", second)
	if err != nil {
		t.Fatalf("open second: %v", err)
	}
	if got2 != plaintext {
		t.Fatalf("open second = %q, want fixture secret", got2)
	}

	var env envelope
	if err := json.Unmarshal([]byte(first), &env); err != nil {
		t.Fatalf("envelope json: %v", err)
	}
	if env.Format != FormatName || env.Version != EnvelopeVersion || env.KeyID != TestActiveKeyID {
		t.Fatalf("envelope header = %+v", env)
	}
}

func TestOpenFailsClosedOnAADCopyAndTamper(t *testing.T) {
	t.Cleanup(ResetForTest)
	if err := InstallTestKeyring(); err != nil {
		t.Fatalf("install test keyring: %v", err)
	}
	env, err := Seal(11, "1001", "secret-a")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := Open(12, "1001", env); err != ErrAuthFailed {
		t.Fatalf("copied to another api key id: err=%v", err)
	}
	if _, err := Open(11, "1002", env); err != ErrAuthFailed {
		t.Fatalf("copied to another pid: err=%v", err)
	}

	tampered := []byte(env)
	tampered[len(tampered)-2] ^= 0x01
	if _, err := Open(11, "1001", string(tampered)); err != ErrAuthFailed && err != ErrInvalidEnvelope && err != ErrInvalidBase64 {
		t.Fatalf("tampered envelope err=%v", err)
	}

	truncated := env[:len(env)/2]
	if _, err := Open(11, "1001", truncated); err == nil {
		t.Fatal("truncated envelope must fail")
	}
}

func TestParseEnvelopeRejectsMalformedInput(t *testing.T) {
	t.Cleanup(ResetForTest)
	if err := InstallTestKeyring(); err != nil {
		t.Fatalf("install test keyring: %v", err)
	}
	valid, err := Seal(3, "1001", "fixture-secret")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	var env envelope
	if err := json.Unmarshal([]byte(valid), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	cases := []struct {
		name string
		raw  string
		want error
	}{
		{name: "plaintext", raw: "fixture-secret", want: ErrPlaintext},
		{name: "empty", raw: "", want: ErrPlaintextEmpty},
		{name: "unknown format", raw: replaceJSONField(t, valid, "format", "other"), want: ErrUnknownFormat},
		{name: "unknown version", raw: replaceJSONField(t, valid, "version", 2), want: ErrUnknownVersion},
		{name: "missing nonce", raw: `{"format":"epusdt.api-key-secret","version":1,"key_id":"test-master-v1","ciphertext":"abc"}`, want: ErrMissingField},
		{name: "duplicate field", raw: `{"format":"epusdt.api-key-secret","format":"epusdt.api-key-secret","version":1,"key_id":"test-master-v1","nonce":"AAAAAAAAAAAA","ciphertext":"aaaaaaaaaaaaaaaaaaaaaa"}`, want: ErrDuplicateField},
		{name: "unknown field", raw: `{"format":"epusdt.api-key-secret","version":1,"key_id":"test-master-v1","nonce":"AAAAAAAAAAAA","ciphertext":"aaaaaaaaaaaaaaaaaaaaaa","extra":1}`, want: ErrInvalidEnvelope},
		{name: "padded base64", raw: replaceJSONField(t, valid, "nonce", env.Nonce+"="), want: ErrInvalidBase64},
		{name: "std base64 alphabet", raw: replaceJSONField(t, valid, "nonce", "++++++++////"), want: ErrInvalidBase64},
		{name: "trailing", raw: valid + `{"x":1}`, want: ErrTrailingData},
		{name: "unknown key id", raw: replaceJSONField(t, valid, "key_id", "missing-key"), want: ErrUnknownKeyID},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Open(3, "1001", tc.raw)
			if err != tc.want {
				t.Fatalf("err=%v (%s), want %v", err, ClassOf(err), tc.want)
			}
			if secret := strings.ToLower(err.Error()); strings.Contains(secret, "fixture-secret") || strings.Contains(secret, strings.ToLower(env.Ciphertext)) {
				t.Fatalf("error leaked sensitive material: %v", err)
			}
		})
	}
}

func TestKeyringRejectsIncompleteAndWrongLengthKeys(t *testing.T) {
	if _, err := NewKeyring("", "", nil); err != ErrActiveKeyMissing {
		t.Fatalf("empty keyring err=%v", err)
	}
	if _, err := NewKeyring("bad ID", TestActiveKeyHex, nil); err == nil {
		t.Fatal("invalid key id must fail")
	}
	if _, err := NewKeyring(TestActiveKeyID, "short", nil); err == nil {
		t.Fatal("short key must fail")
	}
	if _, err := NewKeyring(TestActiveKeyID, TestActiveKeyHex, map[string]string{TestActiveKeyID: TestPreviousKeyHex}); err == nil {
		t.Fatal("conflicting duplicate key id must fail")
	}
}

func TestOverlappingRotationDecryptsOldAndWritesNew(t *testing.T) {
	t.Cleanup(ResetForTest)
	oldRing, err := NewKeyring(TestPreviousKeyID, TestPreviousKeyHex, nil)
	if err != nil {
		t.Fatalf("old ring: %v", err)
	}
	Replace(oldRing)
	oldEnv, err := Seal(9, "1001", "old-secret")
	if err != nil {
		t.Fatalf("seal old: %v", err)
	}

	if err := InstallRotatedTestKeyring(); err != nil {
		t.Fatalf("rotated ring: %v", err)
	}
	got, err := Open(9, "1001", oldEnv)
	if err != nil {
		t.Fatalf("open old with overlapping ring: %v", err)
	}
	if got != "old-secret" {
		t.Fatalf("old secret mismatch")
	}
	newEnv, err := Seal(9, "1001", "new-secret")
	if err != nil {
		t.Fatalf("seal new: %v", err)
	}
	var env envelope
	if err := json.Unmarshal([]byte(newEnv), &env); err != nil {
		t.Fatalf("new envelope: %v", err)
	}
	if env.KeyID != TestActiveKeyID {
		t.Fatalf("new envelope key_id=%s, want %s", env.KeyID, TestActiveKeyID)
	}

	Replace(oldRing)
	if _, err := Open(9, "1001", newEnv); err != ErrUnknownKeyID {
		t.Fatalf("new envelope without new key err=%v, want unknown key id", err)
	}
}

func TestOpenWithoutKeyringFailsClosed(t *testing.T) {
	ResetForTest()
	if _, err := Seal(1, "1001", "x"); err != ErrKeyringUnavailable {
		t.Fatalf("seal without keyring err=%v", err)
	}
	if _, err := Open(1, "1001", `{"format":"epusdt.api-key-secret","version":1,"key_id":"test-master-v1","nonce":"AAAAAAAAAAAA","ciphertext":"aaaaaaaaaaaaaaaaaaaaaa"}`); err != ErrKeyringUnavailable {
		t.Fatalf("open without keyring err=%v", err)
	}
}

func TestParseDecryptKeys(t *testing.T) {
	got, err := ParseDecryptKeys(TestPreviousKeyID + "=" + TestPreviousKeyHex + "," + TestActiveKeyID + "=" + TestActiveKeyHex)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got[TestPreviousKeyID] != TestPreviousKeyHex || got[TestActiveKeyID] != TestActiveKeyHex {
		t.Fatalf("parse result = %#v", got)
	}
	if _, err := ParseDecryptKeys("nolequals"); err == nil {
		t.Fatal("expected parse error")
	}
}

func replaceJSONField(t *testing.T, raw, key string, value any) string {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	obj[key] = value
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return string(out)
}

func TestNonceLengthIsTwelveBytes(t *testing.T) {
	t.Cleanup(ResetForTest)
	if err := InstallTestKeyring(); err != nil {
		t.Fatalf("install test keyring: %v", err)
	}
	raw, err := Seal(1, "1001", "fixture")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(env.Nonce)
	if err != nil {
		t.Fatalf("nonce decode: %v", err)
	}
	if len(nonce) != GCMNonceSize {
		t.Fatalf("nonce length=%d, want %d", len(nonce), GCMNonceSize)
	}
}

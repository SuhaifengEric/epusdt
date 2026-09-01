package data

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GMWalletApp/epusdt/internal/testutil"
	"github.com/GMWalletApp/epusdt/model/dao"
	"github.com/GMWalletApp/epusdt/model/mdb"
	"github.com/GMWalletApp/epusdt/security/apikeysecret"
	appLog "github.com/GMWalletApp/epusdt/util/log"
	"github.com/libtnb/sqlite"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

const fixtureSecret = "fixture-only-merchant-secret"

func TestCreateApiKeyStoresEnvelopeNotPlaintext(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	row := &mdb.ApiKey{Name: "sealed", Pid: "2001", SecretKey: fixtureSecret, Status: mdb.ApiKeyStatusEnable}
	testutil.CreateApiKey(t, row)

	var stored string
	if err := dao.Mdb.Model(&mdb.ApiKey{}).Select("secret_key").Where("id = ?", row.ID).Scan(&stored).Error; err != nil {
		t.Fatalf("read stored secret: %v", err)
	}
	if stored == fixtureSecret || strings.Contains(stored, fixtureSecret) {
		t.Fatal("sqlite stored plaintext merchant secret")
	}
	var env map[string]any
	if err := json.Unmarshal([]byte(stored), &env); err != nil {
		t.Fatalf("stored value is not json envelope: %v", err)
	}
	if env["format"] != apikeysecret.FormatName || env["key_id"] != apikeysecret.TestActiveKeyID {
		t.Fatalf("envelope header = %#v", env)
	}

	got, err := HMACSecret(row)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != fixtureSecret {
		t.Fatalf("decrypted secret mismatch")
	}
}

func TestMigratePlaintextIsIdempotentAndRuntimeRejectsPlaintext(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	if err := dao.Mdb.Exec(`INSERT INTO api_keys (name, pid, secret_key, status, created_at, updated_at) VALUES (?,?,?,?, datetime('now'), datetime('now'))`,
		"legacy", "3001", fixtureSecret, mdb.ApiKeyStatusEnable).Error; err != nil {
		t.Fatalf("insert plaintext: %v", err)
	}

	report, err := ScanApiKeySecrets()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if report.Plaintext < 1 {
		t.Fatalf("expected plaintext rows, got %+v", report)
	}

	first, err := MigratePlaintextApiKeySecrets()
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if first.Plaintext != 0 || first.DecryptErr != 0 || first.Corrupt != 0 {
		t.Fatalf("after migrate: %+v", first)
	}
	second, err := MigratePlaintextApiKeySecrets()
	if err != nil {
		t.Fatalf("migrate again: %v", err)
	}
	if second.Plaintext != 0 || second.DecryptOK != first.DecryptOK {
		t.Fatalf("idempotent migrate changed counts: first=%+v second=%+v", first, second)
	}

	row := &mdb.ApiKey{}
	if err := dao.Mdb.Where("pid = ?", "3001").Take(row).Error; err != nil {
		t.Fatalf("load row: %v", err)
	}
	got, err := HMACSecret(row)
	if err != nil || got != fixtureSecret {
		t.Fatalf("migrated decrypt secret=%q err=%v", got, err)
	}

	row.SecretKey = fixtureSecret
	if _, err := HMACSecret(row); err != apikeysecret.ErrPlaintext {
		t.Fatalf("runtime plaintext read err=%v, want plaintext forbidden", err)
	}
}

func TestMigrateStopsOnCorruptRow(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	if err := dao.Mdb.Exec(`INSERT INTO api_keys (name, pid, secret_key, status, created_at, updated_at) VALUES (?,?,?,?, datetime('now'), datetime('now'))`,
		"corrupt", "3002", `{"format":"epusdt.api-key-secret","version":1}`, mdb.ApiKeyStatusEnable).Error; err != nil {
		t.Fatalf("insert corrupt: %v", err)
	}
	if _, err := MigratePlaintextApiKeySecrets(); err == nil {
		t.Fatal("expected migrate to stop on corrupt row")
	}
}

func TestReencryptUsesActiveKeyAndDropsOldKeyAfterRewrite(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	oldRing, err := apikeysecret.NewKeyring(apikeysecret.TestPreviousKeyID, apikeysecret.TestPreviousKeyHex, nil)
	if err != nil {
		t.Fatalf("old ring: %v", err)
	}
	apikeysecret.Replace(oldRing)
	row := &mdb.ApiKey{Name: "rotate", Pid: "4001", SecretKey: fixtureSecret, Status: mdb.ApiKeyStatusEnable}
	testutil.CreateApiKey(t, row)

	if err := apikeysecret.InstallRotatedTestKeyring(); err != nil {
		t.Fatalf("rotated ring: %v", err)
	}
	got, err := HMACSecret(row)
	if err != nil || got != fixtureSecret {
		t.Fatalf("old envelope with overlapping ring: secret=%q err=%v", got, err)
	}

	report, err := ReencryptApiKeySecrets()
	if err != nil {
		t.Fatalf("reencrypt: %v", err)
	}
	if report.DecryptOK != report.Total || report.ByKeyID[apikeysecret.TestPreviousKeyID] != 0 {
		t.Fatalf("reencrypt report=%+v", report)
	}
	if report.ByKeyID[apikeysecret.TestActiveKeyID] == 0 {
		t.Fatalf("expected active key ids after reencrypt: %+v", report.ByKeyID)
	}

	activeOnly, err := apikeysecret.NewKeyring(apikeysecret.TestActiveKeyID, apikeysecret.TestActiveKeyHex, nil)
	if err != nil {
		t.Fatalf("active only: %v", err)
	}
	apikeysecret.Replace(activeOnly)
	if err := dao.Mdb.Where("id = ?", row.ID).Take(row).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, err = HMACSecret(row)
	if err != nil || got != fixtureSecret {
		t.Fatalf("after dropping old key: secret=%q err=%v", got, err)
	}
}

func TestSqliteBackupRestoreKeepsDecryptableSecrets(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	row := &mdb.ApiKey{Name: "backup", Pid: "5001", SecretKey: fixtureSecret, Status: mdb.ApiKeyStatusEnable}
	testutil.CreateApiKey(t, row)

	type pragmaRow struct {
		Seq  int
		Name string
		File string
	}
	var dbs []pragmaRow
	if err := dao.Mdb.Raw("PRAGMA database_list").Scan(&dbs).Error; err != nil {
		t.Fatalf("database_list: %v", err)
	}
	var path string
	for _, db := range dbs {
		if db.Name == "main" {
			path = db.File
		}
	}
	if path == "" {
		t.Fatal("missing sqlite main path")
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sqlite: %v", err)
	}
	backup := filepath.Join(t.TempDir(), "api-keys-backup.db")
	if err := os.WriteFile(backup, payload, 0o600); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	restored, err := gorm.Open(sqlite.Open(backup), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{SingularTable: true},
		Logger:         logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	var stored string
	if err := restored.Raw("SELECT secret_key FROM api_keys WHERE pid = ?", "5001").Scan(&stored).Error; err != nil {
		t.Fatalf("restored select: %v", err)
	}
	if strings.Contains(stored, fixtureSecret) {
		t.Fatal("backup contains plaintext secret")
	}
	got, err := apikeysecret.Open(row.ID, "5001", stored)
	if err != nil || got != fixtureSecret {
		t.Fatalf("restore decrypt secret=%q err=%v", got, err)
	}
}

func TestHMACSecretFailureLogsDoNotLeakMaterial(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	core, logs := observer.New(zapcore.ErrorLevel)
	prev := appLog.Sugar
	appLog.Sugar = zap.New(core).Sugar()
	t.Cleanup(func() { appLog.Sugar = prev })

	row := &mdb.ApiKey{Name: "leak", Pid: "6001", SecretKey: fixtureSecret, Status: mdb.ApiKeyStatusEnable}
	testutil.CreateApiKey(t, row)
	row.Pid = "other-pid"
	_, _ = HMACSecret(row)

	if logs.Len() == 0 {
		t.Fatal("expected failure log")
	}
	for _, entry := range logs.All() {
		msg := strings.ToLower(entry.Message + " " + entry.LoggerName)
		encoded, _ := json.Marshal(entry.Context)
		blob := strings.ToLower(string(encoded) + " " + msg)
		if strings.Contains(blob, strings.ToLower(fixtureSecret)) || strings.Contains(blob, "ciphertext") || strings.Contains(blob, row.SecretKey) {
			t.Fatalf("log leaked sensitive material: %s", blob)
		}
	}
}

func TestCopiedEnvelopeToAnotherRowFailsClosed(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	src := &mdb.ApiKey{Name: "src", Pid: "7001", SecretKey: fixtureSecret, Status: mdb.ApiKeyStatusEnable}
	testutil.CreateApiKey(t, src)
	dst := &mdb.ApiKey{Name: "dst", Pid: "7002", SecretKey: "other-fixture-secret", Status: mdb.ApiKeyStatusEnable}
	testutil.CreateApiKey(t, dst)

	if err := dao.Mdb.Model(&mdb.ApiKey{}).Where("id = ?", dst.ID).Update("secret_key", src.SecretKey).Error; err != nil {
		t.Fatalf("copy envelope: %v", err)
	}
	if err := dao.Mdb.Where("id = ?", dst.ID).Take(dst).Error; err != nil {
		t.Fatalf("reload dst: %v", err)
	}
	if _, err := HMACSecret(dst); err != apikeysecret.ErrAuthFailed {
		t.Fatalf("copied envelope err=%v, want auth failure", err)
	}
}

func TestMissingKeyringFailsClosed(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()
	row := &mdb.ApiKey{Name: "noring", Pid: "8001", SecretKey: fixtureSecret, Status: mdb.ApiKeyStatusEnable}
	testutil.CreateApiKey(t, row)
	apikeysecret.ResetForTest()
	if _, err := HMACSecret(row); err != apikeysecret.ErrKeyringUnavailable {
		t.Fatalf("err=%v, want keyring unavailable", err)
	}
}

package data

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/GMWalletApp/epusdt/model/dao"
	"github.com/GMWalletApp/epusdt/model/mdb"
	"github.com/GMWalletApp/epusdt/security/apikeysecret"
	"github.com/GMWalletApp/epusdt/util/log"
	"gorm.io/gorm"
)

// HMACSecret decrypts the merchant HMAC secret for an API key row.
// The GORM-mapped SecretKey field stays as the envelope and is never overwritten
// with plaintext. Failures are low-sensitivity and do not include credentials.
func HMACSecret(row *mdb.ApiKey) (string, error) {
	if row == nil || row.ID == 0 {
		return "", apikeysecret.ErrMissingField
	}
	secret, err := apikeysecret.Open(row.ID, row.Pid, row.SecretKey)
	if err != nil {
		logSecretFailure(row.ID, err)
		return "", err
	}
	return secret, nil
}

func logSecretFailure(id uint64, err error) {
	if log.Sugar == nil {
		return
	}
	log.Sugar.Errorw("api key secret unavailable", "api_key_id", id, "class", apikeysecret.ClassOf(err))
}

func sealAndStore(tx *gorm.DB, row *mdb.ApiKey, plaintext string) error {
	if row == nil || row.ID == 0 {
		return apikeysecret.ErrMissingField
	}
	sealed, err := apikeysecret.Seal(row.ID, row.Pid, plaintext)
	if err != nil {
		logSecretFailure(row.ID, err)
		return err
	}
	if err := tx.Model(row).Update("secret_key", sealed).Error; err != nil {
		return err
	}
	row.SecretKey = sealed
	return nil
}

func persistApiKeyWithPlaintext(row *mdb.ApiKey, plaintext string) error {
	plaintext = strings.TrimSpace(plaintext)
	if row == nil {
		return apikeysecret.ErrMissingField
	}
	if plaintext == "" {
		return apikeysecret.ErrPlaintextEmpty
	}
	return dao.Mdb.Transaction(func(tx *gorm.DB) error {
		row.SecretKey = ""
		if err := tx.Create(row).Error; err != nil {
			return err
		}
		return sealAndStore(tx, row, plaintext)
	})
}

// UpdateApiKeySecret encrypts a new merchant secret for an existing row.
func UpdateApiKeySecret(id uint64, plaintext string) error {
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" {
		return apikeysecret.ErrPlaintextEmpty
	}
	row, err := GetApiKeyByID(id)
	if err != nil {
		return err
	}
	if row == nil || row.ID == 0 {
		return fmt.Errorf("api key not found")
	}
	return dao.Mdb.Transaction(func(tx *gorm.DB) error {
		return sealAndStore(tx, row, plaintext)
	})
}

type apiKeySecretRow struct {
	ID        uint64 `gorm:"column:id"`
	Pid       string `gorm:"column:pid"`
	SecretKey string `gorm:"column:secret_key"`
}

// SecretScanReport is a count-only inventory of api_keys.secret_key storage.
// It never includes secrets, envelopes, or other field values.
type SecretScanReport struct {
	Total      int                 `json:"total"`
	Envelope   int                 `json:"envelope"`
	Plaintext  int                 `json:"plaintext"`
	Corrupt    int                 `json:"corrupt"`
	DecryptOK  int                 `json:"decrypt_ok"`
	DecryptErr int                 `json:"decrypt_err"`
	ByKeyID    map[string]int      `json:"by_key_id,omitempty"`
	Failures   []SecretScanFailure `json:"failures,omitempty"`
}

// SecretScanFailure identifies a row by ID and error class only.
type SecretScanFailure struct {
	ID    uint64 `json:"id"`
	Class string `json:"class"`
}

func listApiKeySecretRows(includeDeleted bool) ([]apiKeySecretRow, error) {
	q := dao.Mdb.Unscoped().Model(&mdb.ApiKey{}).Select("id", "pid", "secret_key")
	if !includeDeleted {
		q = q.Where("deleted_at IS NULL")
	}
	var rows []apiKeySecretRow
	if err := q.Order("id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// ScanApiKeySecrets counts storage formats without printing field contents.
func ScanApiKeySecrets() (SecretScanReport, error) {
	rows, err := listApiKeySecretRows(false)
	if err != nil {
		return SecretScanReport{}, err
	}
	report := SecretScanReport{ByKeyID: map[string]int{}}
	for _, row := range rows {
		report.Total++
		class, keyID := inspectSecretRow(row)
		switch class {
		case "envelope":
			report.Envelope++
			if keyID != "" {
				report.ByKeyID[keyID]++
			}
			if _, err := apikeysecret.Open(row.ID, row.Pid, row.SecretKey); err != nil {
				report.DecryptErr++
				report.Failures = append(report.Failures, SecretScanFailure{ID: row.ID, Class: apikeysecret.ClassOf(err)})
			} else {
				report.DecryptOK++
			}
		case apikeysecret.ClassPlaintext, apikeysecret.ClassPlaintextEmpty:
			report.Plaintext++
			report.Failures = append(report.Failures, SecretScanFailure{ID: row.ID, Class: class})
		default:
			report.Corrupt++
			report.Failures = append(report.Failures, SecretScanFailure{ID: row.ID, Class: class})
		}
	}
	return report, nil
}

func inspectSecretRow(row apiKeySecretRow) (class, keyID string) {
	stored := strings.TrimSpace(row.SecretKey)
	if stored == "" {
		return apikeysecret.ClassPlaintextEmpty, ""
	}
	if !apikeysecret.LooksLikeEnvelope(stored) {
		return apikeysecret.ClassPlaintext, ""
	}
	env := struct {
		KeyID string `json:"key_id"`
	}{}
	jsonUnmarshalKeyID(stored, &env.KeyID)
	_, err := apikeysecret.Open(row.ID, row.Pid, stored)
	if err == nil {
		return "envelope", env.KeyID
	}
	// parse-level failures are corrupt; auth/key failures still count as envelopes
	switch apikeysecret.ClassOf(err) {
	case apikeysecret.ClassAuthFailed, apikeysecret.ClassUnknownKeyID, apikeysecret.ClassKeyringUnavailable, apikeysecret.ClassActiveKeyMissing:
		return "envelope", env.KeyID
	default:
		return apikeysecret.ClassOf(err), env.KeyID
	}
}

func jsonUnmarshalKeyID(raw string, dest *string) {
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(raw))
	if err := dec.Decode(&obj); err != nil {
		return
	}
	if v, ok := obj["key_id"].(string); ok {
		*dest = v
	}
}

// RequireApiKeySecretsProtected fails closed when any live row is plaintext,
// corrupt, or not decryptable with the current keyring.
func RequireApiKeySecretsProtected() error {
	report, err := ScanApiKeySecrets()
	if err != nil {
		return err
	}
	if report.Plaintext > 0 || report.Corrupt > 0 || report.DecryptErr > 0 {
		return fmt.Errorf("api key secrets are not protected: total=%d envelope=%d plaintext=%d corrupt=%d decrypt_ok=%d decrypt_err=%d",
			report.Total, report.Envelope, report.Plaintext, report.Corrupt, report.DecryptOK, report.DecryptErr)
	}
	return nil
}

// MigratePlaintextApiKeySecrets encrypts leftover plaintext rows with the active
// key. Envelope rows are left unchanged. A single failure aborts the batch.
func MigratePlaintextApiKeySecrets() (SecretScanReport, error) {
	before, err := ScanApiKeySecrets()
	if err != nil {
		return before, err
	}
	rows, err := listApiKeySecretRows(false)
	if err != nil {
		return before, err
	}
	for _, row := range rows {
		class, _ := inspectSecretRow(row)
		switch class {
		case "envelope":
			continue
		case apikeysecret.ClassPlaintext:
			if err := migratePlaintextRow(row); err != nil {
				after, _ := ScanApiKeySecrets()
				after.Failures = append([]SecretScanFailure{{ID: row.ID, Class: apikeysecret.ClassOf(err)}}, after.Failures...)
				return after, fmt.Errorf("migrate api key id=%d class=%s", row.ID, apikeysecret.ClassOf(err))
			}
		default:
			after, _ := ScanApiKeySecrets()
			return after, fmt.Errorf("migrate api key id=%d class=%s", row.ID, class)
		}
	}
	return ScanApiKeySecrets()
}

func migratePlaintextRow(row apiKeySecretRow) error {
	plaintext := row.SecretKey
	if strings.TrimSpace(plaintext) == "" {
		return apikeysecret.ErrPlaintextEmpty
	}
	if apikeysecret.LooksLikeEnvelope(plaintext) {
		return apikeysecret.ErrInvalidEnvelope
	}
	sealed, err := apikeysecret.Seal(row.ID, row.Pid, plaintext)
	if err != nil {
		logSecretFailure(row.ID, err)
		return err
	}
	got, err := apikeysecret.Open(row.ID, row.Pid, sealed)
	if err != nil {
		logSecretFailure(row.ID, err)
		return err
	}
	if got != plaintext {
		return apikeysecret.ErrAuthFailed
	}
	return dao.Mdb.Model(&mdb.ApiKey{}).Where("id = ?", row.ID).Update("secret_key", sealed).Error
}

// ReencryptApiKeySecrets rewrites every envelope with the active master key.
// Plaintext or corrupt rows abort the batch; they must be migrated first.
func ReencryptApiKeySecrets() (SecretScanReport, error) {
	rows, err := listApiKeySecretRows(false)
	if err != nil {
		return SecretScanReport{}, err
	}
	for _, row := range rows {
		class, _ := inspectSecretRow(row)
		if class != "envelope" {
			report, _ := ScanApiKeySecrets()
			return report, fmt.Errorf("reencrypt api key id=%d class=%s", row.ID, class)
		}
		plain, err := apikeysecret.Open(row.ID, row.Pid, row.SecretKey)
		if err != nil {
			logSecretFailure(row.ID, err)
			report, _ := ScanApiKeySecrets()
			return report, fmt.Errorf("reencrypt api key id=%d class=%s", row.ID, apikeysecret.ClassOf(err))
		}
		if err := dao.Mdb.Transaction(func(tx *gorm.DB) error {
			model := &mdb.ApiKey{}
			model.ID = row.ID
			model.Pid = row.Pid
			return sealAndStore(tx, model, plain)
		}); err != nil {
			report, _ := ScanApiKeySecrets()
			return report, fmt.Errorf("reencrypt api key id=%d class=%s", row.ID, apikeysecret.ClassOf(err))
		}
	}
	return ScanApiKeySecrets()
}

package install

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GMWalletApp/epusdt/config"
	"github.com/GMWalletApp/epusdt/model/dao"
	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

func resetInstallTestState(t *testing.T) {
	t.Helper()

	closeInstallDatabases()
	dao.ResetMdbTableInitForTest()
	config.SetConfigPath("")
	viper.Reset()

	t.Cleanup(func() {
		closeInstallDatabases()
		dao.ResetMdbTableInitForTest()
		config.SetConfigPath("")
		viper.Reset()
	})
}

func redactEnv(content string) string {
	var b strings.Builder
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "api_key_secret_active_key=") || strings.HasPrefix(trimmed, "api_key_secret_decrypt_keys=") {
			if idx := strings.IndexByte(trimmed, '='); idx >= 0 {
				b.WriteString(trimmed[:idx+1])
				b.WriteString("[redacted]\n")
				continue
			}
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func envValue(content, key string) string {
	prefix := key + "="
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func newInstallTestAPI(envPath string) (*echo.Echo, *installHandler) {
	h := &installHandler{envFilePath: envPath, done: make(chan struct{})}
	e := echo.New()
	e.POST("/install", h.Submit)
	return e, h
}

func submitInstallRequest(t *testing.T, e *echo.Echo, payload string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/install", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return body
}

func assertDoneClosed(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("handler did not close done channel within timeout")
	}
}

func changeInstalledAdminPassword(t *testing.T, envPath, newPassword string) {
	t.Helper()

	if err := initInstallConfig(envPath); err != nil {
		t.Fatalf("reopen install config: %v", err)
	}
	if err := initInstallDatabases(); err != nil {
		t.Fatalf("reopen install databases: %v", err)
	}
	defer closeInstallDatabases()

	user, err := data.GetAdminUserByUsername("admin")
	if err != nil {
		t.Fatalf("load admin user: %v", err)
	}
	if user.ID == 0 {
		t.Fatal("expected seeded admin user")
	}
	if err := data.UpdateAdminUserPassword(uint64(user.ID), newPassword); err != nil {
		t.Fatalf("change admin password: %v", err)
	}
}

func TestInstallDefaults(t *testing.T) {
	d := InstallDefaults()
	if d.AppName != "epusdt" {
		t.Errorf("AppName = %q, want epusdt", d.AppName)
	}
	if d.HttpBindAddr != "127.0.0.1" {
		t.Errorf("HttpBindAddr = %q, want 127.0.0.1", d.HttpBindAddr)
	}
	if d.HttpBindPort != 8000 {
		t.Errorf("HttpBindPort = %d, want 8000", d.HttpBindPort)
	}
	if d.OrderExpirationTime != 10 {
		t.Errorf("OrderExpirationTime = %d, want 10", d.OrderExpirationTime)
	}
}

func TestWriteEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	req := &InstallRequest{
		AppName:             "myapp",
		AppURI:              "http://1.2.3.4:8000",
		HttpBindAddr:        "0.0.0.0",
		HttpBindPort:        9000,
		RuntimeRootPath:     "./runtime",
		LogSavePath:         "./logs",
		OrderExpirationTime: 15,
		OrderNoticeMaxRetry: 3,
	}
	if err := writeEnvFile(path, req, false); err != nil {
		t.Fatalf("writeEnvFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	content := string(data)

	for _, want := range []string{
		"app_name=myapp",
		"app_uri=http://1.2.3.4:8000",
		"http_listen=0.0.0.0:9000",
		"order_expiration_time=15",
		"order_notice_max_retry=3",
		"db_type=sqlite",
		"install=false",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("env file missing %q\ncontent:\n%s", want, redactEnv(content))
		}
	}
}

func TestInstallAPIDefaults(t *testing.T) {
	h := &installHandler{done: make(chan struct{})}
	e := echo.New()
	e.GET("/install/defaults", h.GetDefaults)

	req := httptest.NewRequest(http.MethodGet, "/install/defaults", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["app_name"] != "epusdt" {
		t.Errorf("app_name = %v, want epusdt", body["app_name"])
	}
	if body["http_bind_addr"] != "127.0.0.1" {
		t.Errorf("http_bind_addr = %v, want 127.0.0.1", body["http_bind_addr"])
	}
	if body["http_bind_port"] != float64(8000) {
		t.Errorf("http_bind_port = %v, want 8000", body["http_bind_port"])
	}
}

func TestInstallServerRootRedirectsToInstall(t *testing.T) {
	dir := t.TempDir()
	wwwRoot := filepath.Join(dir, "www")
	if err := os.MkdirAll(wwwRoot, 0o755); err != nil {
		t.Fatalf("mkdir www root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wwwRoot, "index.html"), []byte("install-ui"), 0o644); err != nil {
		t.Fatalf("write index.html: %v", err)
	}

	e, _ := newInstallServer(filepath.Join(dir, ".env"), wwwRoot)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/install" {
		t.Fatalf("Location = %q, want /install", got)
	}
}

func TestInstallServerServesSPAOnInstallRoute(t *testing.T) {
	dir := t.TempDir()
	wwwRoot := filepath.Join(dir, "www")
	if err := os.MkdirAll(wwwRoot, 0o755); err != nil {
		t.Fatalf("mkdir www root: %v", err)
	}
	const wantBody = "install-ui"
	if err := os.WriteFile(filepath.Join(wwwRoot, "index.html"), []byte(wantBody), 0o644); err != nil {
		t.Fatalf("write index.html: %v", err)
	}

	e, _ := newInstallServer(filepath.Join(dir, ".env"), wwwRoot)

	req := httptest.NewRequest(http.MethodGet, "/install", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); body != wantBody {
		t.Fatalf("body = %q, want %q", body, wantBody)
	}
}

func TestInstallAPISubmitReturnsInitialPassword(t *testing.T) {
	resetInstallTestState(t)

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	e, h := newInstallTestAPI(envPath)

	payload := `{"app_name":"testapp","app_uri":"http://10.0.0.1:8000","http_bind_addr":"0.0.0.0","http_bind_port":8000,"order_expiration_time":10,"order_notice_max_retry":1}`
	rec := submitInstallRequest(t, e, payload)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if got, _ := body["message"].(string); got == "" {
		t.Fatalf("expected success message, got body=%v", body)
	}
	initPassword, _ := body["init_password"].(string)
	if strings.TrimSpace(initPassword) == "" {
		t.Fatalf("expected non-empty init_password, got body=%v", body)
	}
	assertDoneClosed(t, h.done)

	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("env file not written: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "app_uri=http://10.0.0.1:8000") {
		t.Errorf("env file missing app_uri; content:\n%s", redactEnv(content))
	}
	if !strings.Contains(content, "http_listen=0.0.0.0:8000") {
		t.Errorf("env file missing http_listen; content:\n%s", redactEnv(content))
	}
	if !strings.Contains(content, "install=false") {
		t.Errorf("env file missing install=false; content:\n%s", redactEnv(content))
	}
	if rec.Body.String() != "" && strings.Contains(rec.Body.String(), envValue(content, "api_key_secret_active_key")) {
		t.Fatal("install response leaked api key secret master key")
	}
	if got := envValue(content, "api_key_secret_active_key_id"); got != "master-v1" {
		t.Fatalf("active key id = %q, want master-v1", got)
	}
	key := envValue(content, "api_key_secret_active_key")
	if len(key) != 64 {
		t.Fatalf("active key length = %d, want 64 hex chars", len(key))
	}
}

func TestInstallAPISubmitRepeatInstallReturnsSamePasswordWhilePlaintextExists(t *testing.T) {
	resetInstallTestState(t)

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	payload := `{"app_name":"testapp","app_uri":"http://10.0.0.1:8000","http_bind_addr":"0.0.0.0","http_bind_port":8000,"order_expiration_time":10,"order_notice_max_retry":1}`

	e1, h1 := newInstallTestAPI(envPath)
	rec1 := submitInstallRequest(t, e1, payload)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first install status = %d, want 200; body: %s", rec1.Code, rec1.Body.String())
	}
	body1 := decodeBody(t, rec1)
	password1, _ := body1["init_password"].(string)
	if strings.TrimSpace(password1) == "" {
		t.Fatalf("expected first init_password, got body=%v", body1)
	}
	assertDoneClosed(t, h1.done)

	e2, h2 := newInstallTestAPI(envPath)
	rec2 := submitInstallRequest(t, e2, payload)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second install status = %d, want 200; body: %s", rec2.Code, rec2.Body.String())
	}
	body2 := decodeBody(t, rec2)
	password2, _ := body2["init_password"].(string)
	if password2 != password1 {
		t.Fatalf("expected repeat install to return same init_password %q, got %q", password1, password2)
	}
	assertDoneClosed(t, h2.done)
}

func TestInstallAPISubmitRepeatInstallOmitsPasswordAfterPasswordChange(t *testing.T) {
	resetInstallTestState(t)

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	payload := `{"app_name":"testapp","app_uri":"http://10.0.0.1:8000","http_bind_addr":"0.0.0.0","http_bind_port":8000,"order_expiration_time":10,"order_notice_max_retry":1}`

	e1, h1 := newInstallTestAPI(envPath)
	rec1 := submitInstallRequest(t, e1, payload)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first install status = %d, want 200; body: %s", rec1.Code, rec1.Body.String())
	}
	assertDoneClosed(t, h1.done)

	changeInstalledAdminPassword(t, envPath, "new-password-456")

	e2, h2 := newInstallTestAPI(envPath)
	rec2 := submitInstallRequest(t, e2, payload)
	if rec2.Code != http.StatusOK {
		t.Fatalf("repeat install status = %d, want 200; body: %s", rec2.Code, rec2.Body.String())
	}
	body2 := decodeBody(t, rec2)
	if got, ok := body2["init_password"]; ok {
		t.Fatalf("expected init_password to be omitted after password change, got %v", got)
	}
	if got, _ := body2["message"].(string); got == "" {
		t.Fatalf("expected success message, got body=%v", body2)
	}
	assertDoneClosed(t, h2.done)
}

func TestInstallAPISubmitInitFailureKeepsInstallMode(t *testing.T) {
	resetInstallTestState(t)

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	e, h := newInstallTestAPI(envPath)
	payload := `{"app_name":"testapp","app_uri":"http://10.0.0.1:8000","http_bind_addr":"0.0.0.0","http_bind_port":8000,"runtime_root_path":"/dev/null/runtime","order_expiration_time":10,"order_notice_max_retry":1}`
	rec := submitInstallRequest(t, e, payload)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	select {
	case <-h.done:
		t.Fatal("handler should not close done channel on init failure")
	case <-time.After(100 * time.Millisecond):
	}
	contentBytes, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env after init failure: %v", err)
	}
	content := string(contentBytes)
	if !strings.Contains(content, "install=true") {
		t.Fatalf("expected env to keep install=true after failure; content:\n%s", redactEnv(content))
	}
}

func TestInstallAPISubmitMissingURI(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	e, _ := newInstallTestAPI(envPath)
	rec := submitInstallRequest(t, e, `{"app_name":"x"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if _, err := os.Stat(envPath); err == nil {
		t.Error("env file should not have been written for invalid request")
	}
}

func TestInstallAPISubmitInvalidPort(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	e, _ := newInstallTestAPI(envPath)
	rec := submitInstallRequest(t, e, `{"app_uri":"http://example.com","http_bind_port":99999}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(envPath); err == nil {
		t.Error("env file should not have been written for invalid port")
	}
}

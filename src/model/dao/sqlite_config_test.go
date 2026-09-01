package dao

import (
	"path/filepath"
	"testing"

	"github.com/libtnb/sqlite"
	"gorm.io/gorm"
)

func TestConfigureSQLiteUsesRequestedConnectionLimit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "runtime.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	sqlDB, err := configureSQLite(db, runtimeSQLiteMaxOpenConns)
	if err != nil {
		t.Fatalf("configure sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	if got := sqlDB.Stats().MaxOpenConnections; got != runtimeSQLiteMaxOpenConns {
		t.Fatalf("max open connections = %d, want %d", got, runtimeSQLiteMaxOpenConns)
	}
}

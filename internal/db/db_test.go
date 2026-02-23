package db

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDB_New(t *testing.T) {
	// Create a temporary directory for the test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	// Test creating a new database
	database, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			t.Fatalf("Database close failed: %v", err)
		}
	}()

	// Verify database file was created
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}

	// Test basic connectivity
	if err := database.Conn().Ping(); err != nil {
		t.Errorf("Database ping failed: %v", err)
	}
}

func TestDB_Migration(t *testing.T) {
	// Create a temporary directory for the test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			t.Fatalf("Database close failed: %v", err)
		}
	}()

	// Verify all tables were created
	tables := []string{
		"brands", "sets", "collection_items",
		"tags", "set_tags", "collection_item_tags",
		"valuations", "external_cache", "users",
		"schema_migrations",
	}

	for _, table := range tables {
		var count int
		err := database.Conn().QueryRow(
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
			table,
		).Scan(&count)

		if err != nil {
			t.Errorf("Failed to check table %s: %v", table, err)
		}

		if count == 0 {
			t.Errorf("Table %s was not created", table)
		}
	}
}

func TestDB_ConnectionLimits(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			t.Fatalf("Database close failed: %v", err)
		}
	}()

	// Test that connection limits are set
	stats := database.Conn().Stats()

	// This should be non-zero after setup
	if stats.MaxOpenConnections == 0 {
		t.Error("MaxOpenConnections should be set")
	}
}

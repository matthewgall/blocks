package cache

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const externalCacheSchema = `
CREATE TABLE IF NOT EXISTS external_cache (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	provider TEXT NOT NULL CHECK (provider IN ('brickset', 'rebrickable', 'bricklink', 'brickset_daily_limit')),
	cache_key TEXT UNIQUE NOT NULL,
	payload_json TEXT NOT NULL,
	etag TEXT,
	fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	ttl_seconds INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_external_cache_provider_key ON external_cache(provider, cache_key);
CREATE INDEX IF NOT EXISTS idx_external_cache_fetched_at ON external_cache(fetched_at);
`

func NewWithPath(path string) (Cache, error) {
	if path == "" {
		return nil, fmt.Errorf("cache path required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("creating cache directory: %w", err)
	}

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening cache database: %w", err)
	}

	conn.SetMaxOpenConns(10)
	conn.SetMaxIdleConns(10)
	conn.SetConnMaxLifetime(5 * time.Minute)

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("pinging cache database: %w", err)
	}
	if _, err := conn.Exec(externalCacheSchema); err != nil {
		return nil, fmt.Errorf("creating cache schema: %w", err)
	}

	return &cacheImpl{db: conn}, nil
}

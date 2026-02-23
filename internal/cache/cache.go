package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/matthewgall/blocks/internal/models"
)

type Cache interface {
	Get(ctx context.Context, provider models.Provider, key string) (*models.ExternalCache, error)
	Set(ctx context.Context, provider models.Provider, key string, payload interface{}, ttl time.Duration, etag *string) error
	Delete(ctx context.Context, provider models.Provider, key string) error
	ClearExpired(ctx context.Context) error
	ClearAll(ctx context.Context) error
	DB() *sql.DB
}

type cacheImpl struct {
	db *sql.DB
}

func New(db *sql.DB) Cache {
	return &cacheImpl{db: db}
}

func (c *cacheImpl) Get(ctx context.Context, provider models.Provider, key string) (*models.ExternalCache, error) {
	var cache models.ExternalCache
	var fetchedAt string

	err := c.db.QueryRowContext(ctx, `
		SELECT id, provider, cache_key, payload_json, etag, fetched_at, ttl_seconds
		FROM external_cache 
		WHERE provider = ? AND cache_key = ? AND datetime(fetched_at, '+' || ttl_seconds || ' seconds') > datetime('now')
		ORDER BY fetched_at DESC
		LIMIT 1
	`, provider, key).Scan(
		&cache.ID, &cache.Provider, &cache.CacheKey, &cache.PayloadJSON,
		&cache.ETag, &fetchedAt, &cache.TTLSeconds,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("querying cache: %w", err)
	}

	parsedTime, err := time.Parse("2006-01-02 15:04:05", fetchedAt)
	if err != nil {
		// Try alternative format
		parsedTime, err = time.Parse(time.RFC3339, fetchedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing fetched_at time: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("parsing fetched_at time: %w", err)
	}
	cache.FetchedAt = parsedTime

	return &cache, nil
}

func (c *cacheImpl) Set(ctx context.Context, provider models.Provider, key string, payload interface{}, ttl time.Duration, etag *string) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	ttlSeconds := int(ttl.Seconds())

	_, err = c.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO external_cache 
		(provider, cache_key, payload_json, etag, fetched_at, ttl_seconds)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
	`, provider, key, string(payloadJSON), etag, ttlSeconds)

	if err != nil {
		return fmt.Errorf("storing cache entry: %w", err)
	}

	return nil
}

func (c *cacheImpl) Delete(ctx context.Context, provider models.Provider, key string) error {
	_, err := c.db.ExecContext(ctx, `
		DELETE FROM external_cache WHERE provider = ? AND cache_key = ?
	`, provider, key)

	return err
}

func (c *cacheImpl) ClearExpired(ctx context.Context) error {
	_, err := c.db.ExecContext(ctx, `
		DELETE FROM external_cache 
		WHERE datetime(fetched_at, '+' || ttl_seconds || ' seconds') <= datetime('now')
	`)

	return err
}

func (c *cacheImpl) ClearAll(ctx context.Context) error {
	_, err := c.db.ExecContext(ctx, "DELETE FROM external_cache")
	return err
}

func (c *cacheImpl) DB() *sql.DB {
	return c.db
}

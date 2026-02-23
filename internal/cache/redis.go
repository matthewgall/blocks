package cache

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/matthewgall/blocks/internal/models"
	"github.com/redis/go-redis/v9"
)

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
	UseTLS   bool
}

type redisCache struct {
	client    *redis.Client
	db        *sql.DB
	keyPrefix string
}

type redisCacheEntry struct {
	Provider    models.Provider `json:"provider"`
	CacheKey    string          `json:"cache_key"`
	PayloadJSON string          `json:"payload_json"`
	ETag        *string         `json:"etag,omitempty"`
	FetchedAt   time.Time       `json:"fetched_at"`
	TTLSeconds  int             `json:"ttl_seconds"`
}

func NewRedis(db *sql.DB, cfg RedisConfig) (Cache, error) {
	addr := strings.TrimSpace(cfg.Addr)
	if addr == "" {
		return nil, fmt.Errorf("redis address required")
	}

	options := &redis.Options{
		Addr:     addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	}
	if cfg.UseTLS {
		options.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	client := redis.NewClient(options)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("pinging redis: %w", err)
	}

	return &redisCache{client: client, db: db, keyPrefix: "external_cache"}, nil
}

func (c *redisCache) Get(ctx context.Context, provider models.Provider, key string) (*models.ExternalCache, error) {
	value, err := c.client.Get(ctx, c.buildKey(provider, key)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("querying redis cache: %w", err)
	}

	var entry redisCacheEntry
	if err := json.Unmarshal([]byte(value), &entry); err != nil {
		return nil, fmt.Errorf("decoding redis cache: %w", err)
	}

	return &models.ExternalCache{
		Provider:    entry.Provider,
		CacheKey:    entry.CacheKey,
		PayloadJSON: entry.PayloadJSON,
		ETag:        entry.ETag,
		FetchedAt:   entry.FetchedAt,
		TTLSeconds:  entry.TTLSeconds,
	}, nil
}

func (c *redisCache) Set(ctx context.Context, provider models.Provider, key string, payload interface{}, ttl time.Duration, etag *string) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	entry := redisCacheEntry{
		Provider:    provider,
		CacheKey:    key,
		PayloadJSON: string(payloadJSON),
		ETag:        etag,
		FetchedAt:   time.Now().UTC(),
		TTLSeconds:  int(ttl.Seconds()),
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encoding redis cache: %w", err)
	}

	if err := c.client.Set(ctx, c.buildKey(provider, key), encoded, ttl).Err(); err != nil {
		return fmt.Errorf("storing redis cache: %w", err)
	}

	return nil
}

func (c *redisCache) Delete(ctx context.Context, provider models.Provider, key string) error {
	if err := c.client.Del(ctx, c.buildKey(provider, key)).Err(); err != nil {
		return fmt.Errorf("deleting redis cache: %w", err)
	}
	return nil
}

func (c *redisCache) ClearExpired(ctx context.Context) error {
	return nil
}

func (c *redisCache) ClearAll(ctx context.Context) error {
	pattern := c.keyPrefix + ":*"
	iter := c.client.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		if err := c.client.Del(ctx, iter.Val()).Err(); err != nil {
			return fmt.Errorf("clearing redis cache: %w", err)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("scanning redis keys: %w", err)
	}
	return nil
}

func (c *redisCache) DB() *sql.DB {
	return c.db
}

func (c *redisCache) buildKey(provider models.Provider, key string) string {
	return fmt.Sprintf("%s:%s:%s", c.keyPrefix, provider, key)
}

package db

import "fmt"

type migration struct {
	version int
	name    string
	sql     string
}

var migrations = []migration{
	{version: 1, name: "brands", sql: brandsTable},
	{version: 2, name: "sets", sql: setsTable},
	{version: 3, name: "collection_items", sql: collectionItemsTable},
	{version: 4, name: "tags", sql: tagsTable},
	{version: 5, name: "set_tags", sql: setTagsTable},
	{version: 6, name: "collection_item_tags", sql: collectionItemTagsTable},
	{version: 8, name: "valuations", sql: valuationsTable},
	{version: 9, name: "external_cache", sql: externalCacheTable},
	{version: 10, name: "users", sql: usersTable},
	{version: 11, name: "drop_set_external_ids", sql: dropSetExternalIDs},
	{version: 12, name: "collection_item_images", sql: collectionItemImagesTable},
	{version: 13, name: "api_tokens", sql: apiTokensTable},
	{version: 14, name: "api_tokens_enhancements", sql: apiTokensEnhancements},
	{version: 15, name: "index_optimizations", sql: indexOptimizations},
	{version: 16, name: "drop_barcodes", sql: dropBarcodes},
	{version: 17, name: "app_settings", sql: appSettingsTable},
	{version: 18, name: "users_public_collection", sql: usersPublicCollection},
}

func validateMigrations() error {
	if len(migrations) == 0 {
		return fmt.Errorf("no migrations defined")
	}

	seenVersions := make(map[int]bool)
	seenNames := make(map[string]bool)
	prevVersion := 0
	for _, migration := range migrations {
		if migration.version <= 0 {
			return fmt.Errorf("invalid migration version %d", migration.version)
		}
		if seenVersions[migration.version] {
			return fmt.Errorf("duplicate migration version %d", migration.version)
		}
		if seenNames[migration.name] {
			return fmt.Errorf("duplicate migration name %s", migration.name)
		}
		if migration.version <= prevVersion {
			return fmt.Errorf("migration version %d out of order", migration.version)
		}
		seenVersions[migration.version] = true
		seenNames[migration.name] = true
		prevVersion = migration.version
	}

	return nil
}

const schemaMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`

const brandsTable = `
CREATE TABLE IF NOT EXISTS brands (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT UNIQUE NOT NULL,
	kind TEXT NOT NULL CHECK (kind IN ('lego', 'clone', 'generic')),
	notes TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS brands_updated_at
AFTER UPDATE ON brands
BEGIN
	UPDATE brands SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
`

const setsTable = `
CREATE TABLE IF NOT EXISTS sets (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	brand_id INTEGER NOT NULL,
	set_code TEXT NOT NULL,
	name TEXT NOT NULL,
	year INTEGER,
	piece_count INTEGER,
	minifigs INTEGER,
	theme TEXT,
	image_url TEXT,
	notes TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (brand_id) REFERENCES brands(id) ON DELETE CASCADE
);

CREATE TRIGGER IF NOT EXISTS sets_updated_at
AFTER UPDATE ON sets
BEGIN
	UPDATE sets SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE INDEX IF NOT EXISTS idx_sets_brand_id ON sets(brand_id);
CREATE INDEX IF NOT EXISTS idx_sets_set_code ON sets(set_code);
`

const collectionItemsTable = `
CREATE TABLE IF NOT EXISTS collection_items (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	set_id INTEGER NOT NULL,
	quantity INTEGER NOT NULL DEFAULT 1,
	condition TEXT NOT NULL CHECK (condition IN ('sealed', 'open', 'partial', 'custom')),
	location TEXT,
	purchase_price REAL,
	purchase_date DATE,
	missing_notes TEXT,
	status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'sold', 'donated')),
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (set_id) REFERENCES sets(id) ON DELETE CASCADE
);

CREATE TRIGGER IF NOT EXISTS collection_items_updated_at
AFTER UPDATE ON collection_items
BEGIN
	UPDATE collection_items SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE INDEX IF NOT EXISTS idx_collection_items_set_id ON collection_items(set_id);
CREATE INDEX IF NOT EXISTS idx_collection_items_status ON collection_items(status);
`

const tagsTable = `
CREATE TABLE IF NOT EXISTS tags (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT UNIQUE NOT NULL CHECK (name = lower(name)),
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS tags_updated_at
AFTER UPDATE ON tags
BEGIN
	UPDATE tags SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE INDEX IF NOT EXISTS idx_tags_name ON tags(name);
`

const setTagsTable = `
CREATE TABLE IF NOT EXISTS set_tags (
	set_id INTEGER NOT NULL,
	tag_id INTEGER NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (set_id, tag_id),
	FOREIGN KEY (set_id) REFERENCES sets(id) ON DELETE CASCADE,
	FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_set_tags_tag_id ON set_tags(tag_id);
`

const collectionItemTagsTable = `
CREATE TABLE IF NOT EXISTS collection_item_tags (
	collection_item_id INTEGER NOT NULL,
	tag_id INTEGER NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (collection_item_id, tag_id),
	FOREIGN KEY (collection_item_id) REFERENCES collection_items(id) ON DELETE CASCADE,
	FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_collection_item_tags_tag_id ON collection_item_tags(tag_id);
`

const valuationsTable = `
CREATE TABLE IF NOT EXISTS valuations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	set_id INTEGER NOT NULL,
	provider TEXT NOT NULL,
	currency TEXT NOT NULL DEFAULT 'GBP',
	condition TEXT CHECK (condition IN ('sealed', 'open', 'partial', 'custom')),
	metric TEXT,
	value REAL NOT NULL,
	sample_size INTEGER,
	confidence INTEGER CHECK (confidence >= 0 AND confidence <= 100),
	as_of_date DATE NOT NULL,
	raw_json TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (set_id) REFERENCES sets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_valuations_set_id ON valuations(set_id);
CREATE INDEX IF NOT EXISTS idx_valuations_provider ON valuations(provider);
CREATE INDEX IF NOT EXISTS idx_valuations_as_of_date ON valuations(as_of_date);
`

const externalCacheTable = `
CREATE TABLE IF NOT EXISTS external_cache (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	provider TEXT NOT NULL CHECK (provider IN ('brickset', 'rebrickable', 'bricklink')),
	cache_key TEXT UNIQUE NOT NULL,
	payload_json TEXT NOT NULL,
	etag TEXT,
	fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	ttl_seconds INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_external_cache_provider_key ON external_cache(provider, cache_key);
CREATE INDEX IF NOT EXISTS idx_external_cache_fetched_at ON external_cache(fetched_at);
`

const usersTable = `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT UNIQUE NOT NULL,
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'editor', 'viewer')),
	disabled_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
`

const usersPublicCollection = `
ALTER TABLE users ADD COLUMN public_collection_enabled INTEGER NOT NULL DEFAULT 0;
`

const collectionItemImagesTable = `
CREATE TABLE IF NOT EXISTS collection_item_images (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	collection_item_id INTEGER NOT NULL,
	storage_key TEXT NOT NULL,
	content_type TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (collection_item_id) REFERENCES collection_items(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_collection_item_images_item_id ON collection_item_images(collection_item_id);
`

const apiTokensTable = `
CREATE TABLE IF NOT EXISTS api_tokens (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	name TEXT,
	token_hash TEXT NOT NULL UNIQUE,
	scope TEXT NOT NULL CHECK (scope IN ('read', 'write', 'admin')),
	expires_at DATETIME,
	last_used_at DATETIME,
	last_used_ip TEXT,
	last_used_user_agent TEXT,
	revoked_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_revoked_at ON api_tokens(revoked_at);
`

// #nosec G101 -- SQL migration text, not credentials.
const apiTokensEnhancements = `
ALTER TABLE api_tokens RENAME TO api_tokens_old;

CREATE TABLE api_tokens (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	name TEXT,
	token_hash TEXT NOT NULL UNIQUE,
	scope TEXT NOT NULL CHECK (scope IN ('read', 'write', 'admin')),
	expires_at DATETIME,
	last_used_at DATETIME,
	last_used_ip TEXT,
	last_used_user_agent TEXT,
	revoked_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO api_tokens (id, user_id, name, token_hash, scope, expires_at, last_used_at, revoked_at, created_at)
SELECT id, user_id, name, token_hash, scope,
       datetime(created_at, '+90 days'),
       last_used_at,
       revoked_at,
       created_at
FROM api_tokens_old;

DROP TABLE api_tokens_old;

CREATE INDEX idx_api_tokens_user_id ON api_tokens(user_id);
CREATE INDEX idx_api_tokens_token_hash ON api_tokens(token_hash);
CREATE INDEX idx_api_tokens_revoked_at ON api_tokens(revoked_at);
`

const indexOptimizations = `
CREATE INDEX IF NOT EXISTS idx_sets_brand_set_code ON sets(brand_id, set_code);
CREATE INDEX IF NOT EXISTS idx_sets_name ON sets(name);

CREATE INDEX IF NOT EXISTS idx_collection_items_set_condition_status ON collection_items(set_id, condition, status);
CREATE INDEX IF NOT EXISTS idx_collection_items_created_at ON collection_items(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_valuations_set_created_at ON valuations(set_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_collection_item_images_item_created_at ON collection_item_images(collection_item_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_api_tokens_user_revoked_created ON api_tokens(user_id, revoked_at, created_at DESC);
`

const dropSetExternalIDs = `
ALTER TABLE sets RENAME TO sets_old;

CREATE TABLE sets (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	brand_id INTEGER NOT NULL,
	set_code TEXT NOT NULL,
	name TEXT NOT NULL,
	year INTEGER,
	piece_count INTEGER,
	minifigs INTEGER,
	theme TEXT,
	image_url TEXT,
	notes TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (brand_id) REFERENCES brands(id) ON DELETE CASCADE
);

INSERT INTO sets (id, brand_id, set_code, name, year, piece_count, minifigs, theme, image_url, notes, created_at, updated_at)
SELECT id, brand_id, set_code, name, year, piece_count, minifigs, theme, image_url, notes, created_at, updated_at
FROM sets_old;

DROP TABLE sets_old;

CREATE TRIGGER sets_updated_at
AFTER UPDATE ON sets
BEGIN
	UPDATE sets SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE INDEX idx_sets_brand_id ON sets(brand_id);
CREATE INDEX idx_sets_set_code ON sets(set_code);
`

const dropBarcodes = `
DROP TABLE IF EXISTS barcodes;

ALTER TABLE sets RENAME TO sets_old;

CREATE TABLE sets (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	brand_id INTEGER NOT NULL,
	set_code TEXT NOT NULL,
	name TEXT NOT NULL,
	year INTEGER,
	piece_count INTEGER,
	minifigs INTEGER,
	theme TEXT,
	image_url TEXT,
	notes TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (brand_id) REFERENCES brands(id) ON DELETE CASCADE
);

INSERT INTO sets (id, brand_id, set_code, name, year, piece_count, minifigs, theme, image_url, notes, created_at, updated_at)
SELECT id, brand_id, set_code, name, year, piece_count, minifigs, theme, image_url, notes, created_at, updated_at
FROM sets_old;

DROP TABLE sets_old;

CREATE TRIGGER sets_updated_at
AFTER UPDATE ON sets
BEGIN
	UPDATE sets SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE INDEX idx_sets_brand_id ON sets(brand_id);
CREATE INDEX idx_sets_set_code ON sets(set_code);
CREATE INDEX idx_sets_brand_set_code ON sets(brand_id, set_code);
CREATE INDEX idx_sets_name ON sets(name);
`

const appSettingsTable = `
CREATE TABLE IF NOT EXISTS app_settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS app_settings_updated_at
AFTER UPDATE ON app_settings
BEGIN
	UPDATE app_settings SET updated_at = CURRENT_TIMESTAMP WHERE key = NEW.key;
END;
`

package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
}

func New(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("creating database directory: %w", err)
	}

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	db := &DB{conn: conn}

	if err := db.setup(); err != nil {
		return nil, fmt.Errorf("setting up database: %w", err)
	}

	return db, nil
}

func (db *DB) setup() error {
	if err := db.conn.Ping(); err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}

	db.conn.SetMaxOpenConns(25)
	db.conn.SetMaxIdleConns(25)
	db.conn.SetConnMaxLifetime(5 * time.Minute)

	if err := db.migrate(); err != nil {
		return fmt.Errorf("migrating database: %w", err)
	}

	if err := db.ensureUserRoleColumn(); err != nil {
		return fmt.Errorf("ensuring user roles: %w", err)
	}

	if err := db.ensureUserDisabledColumn(); err != nil {
		return fmt.Errorf("ensuring user disabled flag: %w", err)
	}

	return nil
}

func (db *DB) ensureUserRoleColumn() error {
	rows, err := db.conn.Query("PRAGMA table_info(users)")
	if err != nil {
		return err
	}
	defer rows.Close()

	roleFound := false
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull int
		var defaultValue *string
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == "role" {
			roleFound = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if roleFound {
		return nil
	}

	if _, err := db.conn.Exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin','editor','viewer'))"); err != nil {
		return err
	}

	_, err = db.conn.Exec("UPDATE users SET role = 'admin' WHERE role IS NULL OR role = ''")
	return err
}

func (db *DB) ensureUserDisabledColumn() error {
	rows, err := db.conn.Query("PRAGMA table_info(users)")
	if err != nil {
		return err
	}
	defer rows.Close()

	disabledFound := false
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull int
		var defaultValue *string
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == "disabled_at" {
			disabledFound = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if disabledFound {
		return nil
	}

	_, err = db.conn.Exec("ALTER TABLE users ADD COLUMN disabled_at DATETIME")
	return err
}

func (db *DB) migrate() error {
	if err := validateMigrations(); err != nil {
		return err
	}

	if _, err := db.conn.Exec(schemaMigrationsTable); err != nil {
		return fmt.Errorf("creating schema migrations table: %w", err)
	}

	applied, err := db.appliedMigrations()
	if err != nil {
		return fmt.Errorf("fetching applied migrations: %w", err)
	}

	for _, migration := range migrations {
		if applied[migration.version] {
			continue
		}

		tx, err := db.conn.Begin()
		if err != nil {
			return fmt.Errorf("starting migration %d_%s: %w", migration.version, migration.name, err)
		}

		if _, err := tx.Exec(migration.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("executing migration %d_%s: %w", migration.version, migration.name, err)
		}

		if _, err := tx.Exec(
			"INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
			migration.version,
			migration.name,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("recording migration %d_%s: %w", migration.version, migration.name, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %d_%s: %w", migration.version, migration.name, err)
		}
	}

	log.Println("Database migrations completed successfully")
	return nil
}

func (db *DB) appliedMigrations() (map[int]bool, error) {
	rows, err := db.conn.Query("SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return applied, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) Conn() *sql.DB {
	return db.conn
}

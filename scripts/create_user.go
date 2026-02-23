package main

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/matthewgall/blocks/internal/config"
	"github.com/matthewgall/blocks/internal/db"
	"github.com/matthewgall/blocks/internal/models"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	username := flag.String("username", "", "Username for the new user")
	password := flag.String("password", "", "Password for the new user")
	role := flag.String("role", string(models.RoleAdmin), "Role for the new user (admin, editor, viewer)")
	passwordStdin := flag.Bool("password-stdin", false, "Read password from stdin")
	flag.Parse()

	if *username == "" {
		log.Fatal("username is required")
	}

	if *passwordStdin {
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil && err.Error() != "EOF" {
			log.Fatalf("reading password from stdin: %v", err)
		}
		*password = strings.TrimSpace(input)
	}

	if *password == "" {
		log.Fatal("password is required")
	}

	userRole := models.UserRole(strings.TrimSpace(*role))
	if !userRole.Valid() {
		log.Fatalf("invalid role: %s", *role)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	store, err := db.New(cfg.Database.Path)
	if err != nil {
		log.Fatalf("opening database: %v", err)
	}
	defer store.Close()

	if err := ensureUserDoesNotExist(store.Conn(), *username); err != nil {
		log.Fatal(err)
	}

	cost := cfg.Auth.BcryptCost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(*password), cost)
	if err != nil {
		log.Fatalf("hashing password: %v", err)
	}

	if err := createUser(store.Conn(), *username, string(hash), userRole); err != nil {
		log.Fatalf("creating user: %v", err)
	}

	fmt.Printf("Created user: %s\n", *username)
}

func ensureUserDoesNotExist(conn *sql.DB, username string) error {
	var existing string
	err := conn.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&existing)
	if err == nil {
		return fmt.Errorf("user already exists: %s", username)
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("checking existing user: %w", err)
	}
	return nil
}

func createUser(conn *sql.DB, username, passwordHash string, role models.UserRole) error {
	_, err := conn.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		username,
		passwordHash,
		role,
	)
	if err != nil {
		return err
	}
	return nil
}

package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/matthewgall/blocks/internal/config"
)

func TestAuthMiddlewareClearsDeletedUserSession(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Database: config.DatabaseConfig{Path: filepath.Join(tempDir, "blocks.db")},
		Auth:     config.AuthConfig{SessionSecret: "test-secret"},
		App:      config.AppConfig{EmbedAssets: true},
		Uploads: config.UploadsConfig{
			Method: "local",
			Local:  config.UploadsLocalConfig{Directory: filepath.Join(tempDir, "uploads")},
		},
	}

	s := New(cfg)
	defer func() {
		if err := s.db.Close(); err != nil {
			t.Fatalf("Database close failed: %v", err)
		}
	}()

	userID, token := createTestUserToken(t, s, "alice")
	createTestUserToken(t, s, "backup")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	resp := httptest.NewRecorder()
	s.router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid session, got %d", resp.Code)
	}

	if _, err := s.db.Conn().Exec("DELETE FROM users WHERE id = ?", userID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	resp = httptest.NewRecorder()
	s.router.ServeHTTP(resp, req)

	if resp.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after deleted user, got %d", resp.Code)
	}
	if location := resp.Header().Get("Location"); location != "/login" {
		t.Fatalf("expected redirect to /login, got %q", location)
	}

	cookie := findCookie(resp.Result(), "session")
	if cookie == nil {
		t.Fatalf("expected session cookie to be cleared")
	}
	if cookie.Value != "" {
		t.Fatalf("expected empty session cookie value, got %q", cookie.Value)
	}
	if cookie.MaxAge >= 0 && (cookie.Expires.IsZero() || cookie.Expires.After(time.Now())) {
		t.Fatalf("expected cleared session cookie, got MaxAge=%d Expires=%v", cookie.MaxAge, cookie.Expires)
	}
}

func TestListTagsEndpoint(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Database: config.DatabaseConfig{Path: filepath.Join(tempDir, "blocks.db")},
		Auth:     config.AuthConfig{SessionSecret: "test-secret"},
		App:      config.AppConfig{EmbedAssets: true},
		Uploads: config.UploadsConfig{
			Method: "local",
			Local:  config.UploadsLocalConfig{Directory: filepath.Join(tempDir, "uploads")},
		},
	}

	s := New(cfg)
	defer func() {
		if err := s.db.Close(); err != nil {
			t.Fatalf("Database close failed: %v", err)
		}
	}()

	if _, err := s.db.Conn().Exec("INSERT INTO tags (name) VALUES (?), (?)", "botanicals", "space"); err != nil {
		t.Fatalf("insert tags: %v", err)
	}

	userID, token := createTestUserToken(t, s, "bob")
	if userID == 0 || token == "" {
		t.Fatalf("expected test user token")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/tags?q=bot", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	resp := httptest.NewRecorder()
	s.router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}

	body := resp.Body.String()
	if body != "[\"botanicals\"]\n" {
		t.Fatalf("expected botanicals list, got %q", body)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/tags?q=unknown", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	resp = httptest.NewRecorder()
	s.router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	if resp.Body.String() != "[]\n" {
		t.Fatalf("expected empty list, got %q", resp.Body.String())
	}
}

func createTestUserToken(t *testing.T, s *Server, username string) (int64, string) {
	t.Helper()

	passwordHash, err := s.auth.HashPassword("password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	result, err := s.db.Conn().Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		username, passwordHash, "admin",
	)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	userID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("get user id: %v", err)
	}

	token, err := s.auth.GenerateToken(userID, username, "admin")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	return userID, token
}

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

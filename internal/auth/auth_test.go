package auth

import (
	"testing"
	"time"
)

func TestAuthService_HashPassword(t *testing.T) {
	auth := NewAuthService("test-secret")

	password := "test-password"
	hash, err := auth.HashPassword(password)

	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hash == "" {
		t.Error("HashPassword() returned empty hash")
	}

	if hash == password {
		t.Error("HashPassword() returned plain text password")
	}
}

func TestAuthService_CheckPassword(t *testing.T) {
	auth := NewAuthService("test-secret")

	password := "test-password"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	err = auth.CheckPassword(password, hash)
	if err != nil {
		t.Errorf("CheckPassword() with correct password error = %v", err)
	}

	err = auth.CheckPassword("wrong-password", hash)
	if err == nil {
		t.Error("CheckPassword() with wrong password should return error")
	}
}

func TestAuthService_GenerateToken(t *testing.T) {
	auth := NewAuthService("test-secret")

	token, err := auth.GenerateToken(1, "testuser", "admin")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	if token == "" {
		t.Error("GenerateToken() returned empty token")
	}
}

func TestAuthService_ValidateToken(t *testing.T) {
	auth := NewAuthService("test-secret")

	token, err := auth.GenerateToken(1, "testuser", "editor")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	claims, err := auth.ValidateToken(token)
	if err != nil {
		t.Errorf("ValidateToken() error = %v", err)
	}

	if claims.UserID != 1 {
		t.Errorf("ValidateToken() UserID = %v, want %v", claims.UserID, 1)
	}

	if claims.Username != "testuser" {
		t.Errorf("ValidateToken() Username = %v, want %v", claims.Username, "testuser")
	}

	if claims.Role != "editor" {
		t.Errorf("ValidateToken() Role = %v, want %v", claims.Role, "editor")
	}

	if claims.ExpiresAt.Before(time.Now()) {
		t.Error("ValidateToken() token should not be expired")
	}
}

func TestAuthService_ValidateInvalidToken(t *testing.T) {
	auth := NewAuthService("test-secret")

	_, err := auth.ValidateToken("invalid-token")
	if err == nil {
		t.Error("ValidateToken() with invalid token should return error")
	}

	_, err = auth.ValidateToken("")
	if err == nil {
		t.Error("ValidateToken() with empty token should return error")
	}
}

func TestGenerateSessionID(t *testing.T) {
	id, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error = %v", err)
	}

	if id == "" {
		t.Error("GenerateSessionID() returned empty ID")
	}

	// Generate another ID to ensure they're different
	id2, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error = %v", err)
	}

	if id == id2 {
		t.Error("GenerateSessionID() should generate unique IDs")
	}
}

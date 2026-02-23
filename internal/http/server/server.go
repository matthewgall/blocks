package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"math"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"runtime/debug"

	"github.com/go-chi/chi/v5"
	"github.com/matthewgall/blocks/internal/auth"
	"github.com/matthewgall/blocks/internal/cache"
	"github.com/matthewgall/blocks/internal/config"
	"github.com/matthewgall/blocks/internal/db"
	"github.com/matthewgall/blocks/internal/models"
	"github.com/matthewgall/blocks/internal/providers/bricklinkprice"
	"github.com/matthewgall/blocks/internal/providers/bricklinkscrape"
	"github.com/matthewgall/blocks/internal/providers/brickset"
	"github.com/matthewgall/blocks/internal/providers/rebrickable"
	"github.com/matthewgall/blocks/internal/templates"
	"github.com/matthewgall/blocks/internal/uploads"
	"github.com/matthewgall/blocks/internal/version"
	"github.com/matthewgall/blocks/static"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	config             *config.Config
	db                 *db.DB
	auth               *auth.AuthService
	cache              cache.Cache
	router             *chi.Mux
	templates          map[string]*template.Template
	brickset           *brickset.Client
	rebrickable        *rebrickable.Client
	bricklinkPrice     *bricklinkprice.Client
	bricklinkScrape    *bricklinkscrape.Client
	uploads            uploads.Storage
	staticFS           fs.FS
	apiTokensRevokedAt *time.Time
}

type apiTokenView struct {
	ID              int64
	Name            *string
	Scope           string
	CreatedAt       time.Time
	LastUsedAt      *time.Time
	ExpiresAt       *time.Time
	RevokedAt       *time.Time
	RevokedBySecret bool
}

type contextKey string

const userContextKey contextKey = "user"
const csrfContextKey contextKey = "csrf"
const apiTokenScopeContextKey contextKey = "apiTokenScope"

const (
	csrfCookieName      = "csrf_token"
	csrfHeaderName      = "X-CSRF-Token"
	csrfFormField       = "csrf_token"
	maxRequestBodyBytes = 1 << 20
)

const apiTokenTTL = 90 * 24 * time.Hour
const csrfRotateInterval = 3 * time.Hour
const sessionIdleTimeout = 3 * time.Hour
const sessionRefreshInterval = 30 * time.Minute
const passwordMinLength = 14
const passwordMaxLength = 128

const (
	apiTokenScopeRead  = "read"
	apiTokenScopeWrite = "write"
	apiTokenScopeAdmin = "admin"
)

var errAPITokenNotFound = errors.New("api token not found")
var errSessionExpired = errors.New("session expired")

func New(cfg *config.Config) *Server {
	_ = mime.AddExtensionType(".js", "application/javascript")
	_ = mime.AddExtensionType(".mjs", "application/javascript")
	database, err := db.New(cfg.Database.Path)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	log.Printf("Using database: %s", cfg.Database.Path)
	apiTokensRevokedAt, err := ensureSessionSecretFingerprint(database.Conn(), cfg.Auth.SessionSecret)
	if err != nil {
		log.Printf("Warning: failed to validate session secret fingerprint: %v", err)
	}

	cacheImpl := cache.New(database.Conn())
	cacheProvider := strings.ToLower(strings.TrimSpace(cfg.Cache.Provider))
	if cacheProvider == "" {
		cacheProvider = "sqlite"
	}
	switch cacheProvider {
	case "redis":
		redisCache, err := cache.NewRedis(database.Conn(), cache.RedisConfig{
			Addr:     cfg.Cache.Redis.Addr,
			Password: cfg.Cache.Redis.Password,
			DB:       cfg.Cache.Redis.DB,
			UseTLS:   cfg.Cache.Redis.UseTLS,
		})
		if err != nil {
			log.Printf("Warning: failed to initialize redis cache: %v", err)
		} else {
			cacheImpl = redisCache
		}
	case "sqlite":
		if strings.TrimSpace(cfg.Cache.Directory) != "" {
			cachePath := filepath.Join(cfg.Cache.Directory, "external_cache.db")
			cacheDB, err := cache.NewWithPath(cachePath)
			if err != nil {
				log.Printf("Warning: failed to initialize cache DB at %s: %v", cachePath, err)
			} else {
				cacheImpl = cacheDB
			}
		}
	}

	uploadStorage, err := uploads.New(context.Background(), cfg.Uploads)
	if err != nil {
		log.Fatalf("Failed to initialize uploads storage: %v", err)
	}

	var tmpl map[string]*template.Template
	var staticFS fs.FS
	if cfg.App.EmbedAssets {
		tmpl, err = templates.LoadTemplates()
		staticFS = static.FS
	} else {
		tmpl, err = templates.LoadTemplatesFS(os.DirFS("internal/templates"))
		staticFS = os.DirFS("static")
	}
	if err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}

	s := &Server{
		config:             cfg,
		db:                 database,
		auth:               auth.NewAuthService(cfg.Auth.SessionSecret),
		cache:              cacheImpl,
		router:             chi.NewRouter(),
		templates:          tmpl,
		brickset:           brickset.New(&cfg.Providers.Brickset, cacheImpl, cfg.Cache.TTL.Remote),
		rebrickable:        rebrickable.New(&cfg.Providers.Rebrickable, cacheImpl, cfg.Cache.TTL.Remote),
		bricklinkPrice:     bricklinkprice.New(cacheImpl, cfg.Cache.TTL.Remote),
		bricklinkScrape:    bricklinkscrape.New(cacheImpl),
		uploads:            uploadStorage,
		staticFS:           staticFS,
		apiTokensRevokedAt: apiTokensRevokedAt,
	}

	s.setupMiddleware()
	s.setupRoutes()

	return s
}

func (s *Server) setupMiddleware() {
	s.router.Use(s.recoverMiddleware)
	s.router.Use(s.securityHeadersMiddleware)
	s.router.Use(s.corsMiddleware)
	s.router.Use(s.authMiddleware)
	s.router.Use(s.maxBodyMiddleware)
	s.router.Use(s.csrfMiddleware)
	s.router.Use(s.roleMiddleware)
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(self), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; font-src 'self' https://fonts.gstatic.com data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if secureCookieEnabled() {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) maxBodyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) || r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}
		if isMultipartForm(r) {
			next.ServeHTTP(w, r)
			return
		}
		if r.ContentLength > maxRequestBodyBytes {
			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			if token := s.ensureCSRFCookie(w, r); token != "" {
				r = r.WithContext(context.WithValue(r.Context(), csrfContextKey, token))
			}
			next.ServeHTTP(w, r)
			return
		}
		if s.isCSRFExempt(r) {
			next.ServeHTTP(w, r)
			return
		}
		cookieToken := csrfTokenFromRequest(r)
		if cookieToken == "" {
			respondCSRFError(w, r)
			return
		}
		requestToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
		if requestToken == "" {
			requestToken = strings.TrimSpace(s.readCSRFFormValue(w, r))
		}
		if requestToken == "" || !csrfTokensMatch(cookieToken, requestToken) {
			respondCSRFError(w, r)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), csrfContextKey, cookieToken))
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func (s *Server) isCSRFExempt(r *http.Request) bool {
	if r.Method == http.MethodPost && r.URL.Path == "/api/auth/login" {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api") && bearerTokenFromRequest(r) != "" {
		return true
	}
	return false
}

func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if token := csrfTokenFromRequest(r); token != "" {
		if !csrfTokenExpired(token, csrfRotateInterval) {
			return token
		}
	}
	return s.issueCSRFCookie(w)
}

func (s *Server) issueCSRFCookie(w http.ResponseWriter) string {
	token, err := generateCSRFToken()
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		Secure:   secureCookieEnabled(),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

func (s *Server) readCSRFFormValue(w http.ResponseWriter, r *http.Request) string {
	if isMultipartForm(r) {
		maxSize := s.config.Uploads.MaxSize
		if maxSize <= 0 {
			maxSize = 10 * 1024 * 1024
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxSize)
		if err := r.ParseMultipartForm(maxSize); err != nil {
			return ""
		}
		return r.FormValue(csrfFormField)
	}
	if err := r.ParseForm(); err != nil {
		return ""
	}
	return r.FormValue(csrfFormField)
}

func isMultipartForm(r *http.Request) bool {
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	return strings.HasPrefix(contentType, "multipart/form-data")
}

func csrfTokenFromRequest(r *http.Request) string {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func bearerTokenFromRequest(r *http.Request) string {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return ""
	}
	if len(authHeader) < 7 {
		return ""
	}
	if strings.ToLower(authHeader[:7]) != "bearer " {
		return ""
	}
	return strings.TrimSpace(authHeader[7:])
}

func clientIP(r *http.Request) string {
	forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func csrfTokenFromContext(r *http.Request) string {
	value := r.Context().Value(csrfContextKey)
	if token, ok := value.(string); ok {
		return token
	}
	return ""
}

func csrfTokenExpired(token string, maxAge time.Duration) bool {
	issuedAt, ok := csrfTokenIssuedAt(token)
	if !ok {
		return true
	}
	return time.Since(issuedAt) > maxAge
}

func csrfTokenIssuedAt(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	if parts[0] != "v1" {
		return time.Time{}, false
	}
	unixValue, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	if unixValue <= 0 {
		return time.Time{}, false
	}
	return time.Unix(unixValue, 0), true
}

func csrfTokensMatch(expected, actual string) bool {
	if expected == "" || actual == "" {
		return false
	}
	if len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func respondCSRFError(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api") {
		respondJSON(w, http.StatusForbidden, map[string]string{"error": "csrf"})
		return
	}
	http.Error(w, "Invalid CSRF token", http.StatusForbidden)
}

func apiScopeForRequest(r *http.Request) string {
	routePattern := r.URL.Path
	if routeCtx := chi.RouteContext(r.Context()); routeCtx != nil {
		if pattern := routeCtx.RoutePattern(); pattern != "" {
			routePattern = pattern
		}
	}
	key := fmt.Sprintf("%s %s", r.Method, routePattern)
	if scope, ok := apiScopePolicies[key]; ok {
		return scope
	}
	if isSafeMethod(r.Method) {
		return apiTokenScopeRead
	}
	return apiTokenScopeWrite
}

func apiTokenAllowsScope(tokenScope, requiredScope string) bool {
	return apiScopeRank(strings.TrimSpace(tokenScope)) >= apiScopeRank(strings.TrimSpace(requiredScope))
}

func apiScopeRank(scope string) int {
	switch strings.ToLower(scope) {
	case apiTokenScopeAdmin:
		return 3
	case apiTokenScopeWrite:
		return 2
	case apiTokenScopeRead:
		return 1
	default:
		return 0
	}
}

func generateAPIToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(buffer)
	return "blk_" + value, nil
}

func (s *Server) hashAPIToken(token string) string {
	secret := []byte(s.config.Auth.SessionSecret)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

func hashAPITokenLegacy(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *Server) authenticateAPIToken(r *http.Request, token string) (*auth.Claims, string, error) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return nil, "", errAPITokenNotFound
	}
	newHash := s.hashAPIToken(trimmed)
	legacyHash := hashAPITokenLegacy(trimmed)

	tokenID, userID, scope, expiresAt, revokedAt, err := s.lookupAPIToken(newHash)
	usedLegacy := false
	if err != nil {
		if errors.Is(err, errAPITokenNotFound) {
			tokenID, userID, scope, expiresAt, revokedAt, err = s.lookupAPIToken(legacyHash)
			usedLegacy = err == nil
		}
		if err != nil {
			return nil, "", err
		}
	}
	if revokedAt != nil {
		return nil, "", fmt.Errorf("api token revoked")
	}
	if expiresAt != nil && time.Now().After(*expiresAt) {
		return nil, "", fmt.Errorf("api token expired")
	}

	var username string
	var role string
	var disabledAt *time.Time
	row := s.db.Conn().QueryRow(
		"SELECT id, username, role, disabled_at FROM users WHERE id = ?",
		userID,
	)
	if err := row.Scan(&userID, &username, &role, &disabledAt); err != nil {
		return nil, "", err
	}
	if disabledAt != nil {
		return nil, "", fmt.Errorf("user disabled")
	}
	if usedLegacy {
		_, _ = s.db.Conn().Exec("UPDATE api_tokens SET token_hash = ? WHERE id = ?", newHash, tokenID)
	}

	lastUsedIP := clientIP(r)
	lastUsedAgent := strings.TrimSpace(r.UserAgent())
	_, _ = s.db.Conn().Exec(
		"UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP, last_used_ip = ?, last_used_user_agent = ? WHERE id = ?",
		lastUsedIP,
		lastUsedAgent,
		tokenID,
	)

	claims := &auth.Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
	}
	return claims, scope, nil
}

func (s *Server) csrfTokenForRequest(w http.ResponseWriter, r *http.Request) string {
	if token := csrfTokenFromContext(r); token != "" {
		return token
	}
	if token := csrfTokenFromRequest(r); token != "" {
		return token
	}
	return s.issueCSRFCookie(w)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicPaths := []string{"/login", "/setup", "/api/auth/login"}
		isAPI := strings.HasPrefix(r.URL.Path, "/api")
		isStatic := strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/static"
		isSetupPath := strings.HasPrefix(r.URL.Path, "/setup")

		if setupRequired, err := s.isSetupRequired(); err == nil && setupRequired {
			if isStatic || isSetupPath {
				next.ServeHTTP(w, r)
				return
			}
			if isAPI {
				respondJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "setup_required"})
				return
			}
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		} else if err != nil {
			log.Printf("setup check failed: %v", err)
		}

		isPublic := false
		for _, path := range publicPaths {
			if r.URL.Path == path {
				isPublic = true
				break
			}
		}
		if isStatic {
			isPublic = true
		}
		if isSetupPath {
			isPublic = true
		}

		if isAPI && !isPublic {
			if token := bearerTokenFromRequest(r); token != "" {
				claims, scope, err := s.authenticateAPIToken(r, token)
				if err == nil {
					requiredScope := apiScopeForRequest(r)
					if !apiTokenAllowsScope(scope, requiredScope) {
						respondForbidden(w, r)
						return
					}
					ctx := context.WithValue(r.Context(), userContextKey, claims)
					ctx = context.WithValue(ctx, apiTokenScopeContextKey, scope)
					r = r.WithContext(ctx)
					next.ServeHTTP(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				if err := json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"}); err != nil {
					log.Printf("encode unauthorized response: %v", err)
				}
				return
			}
		}

		sessionCookie, err := r.Cookie("session")
		if err == nil && sessionCookie.Value != "" {
			claims, err := s.auth.ValidateToken(sessionCookie.Value)
			if err == nil {
				claims, err = s.refreshClaims(claims)
			}
			if err == nil {
				claims, err = s.ensureSessionActive(w, claims)
			}
			if err == nil {
				ctx := context.WithValue(r.Context(), userContextKey, claims)
				r = r.WithContext(ctx)
			} else {
				if errors.Is(err, sql.ErrNoRows) || errors.Is(err, errUserDisabled) || errors.Is(err, errSessionExpired) {
					auth.ClearSessionCookie(w)
				} else {
					log.Printf("Session validation failed: %v", err)
				}
				if !isPublic {
					if isAPI {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusUnauthorized)
						if err := json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"}); err != nil {
							log.Printf("encode unauthorized response: %v", err)
						}
						return
					}
					http.Redirect(w, r, "/login", http.StatusSeeOther)
					return
				}
			}
		} else if !isPublic {
			if isAPI {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				if err := json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"}); err != nil {
					log.Printf("encode unauthorized response: %v", err)
				}
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

var errUserDisabled = errors.New("user disabled")

func (s *Server) refreshClaims(claims *auth.Claims) (*auth.Claims, error) {
	var username string
	var role string
	var disabledAt sql.NullString

	err := s.db.Conn().QueryRow(
		"SELECT username, role, disabled_at FROM users WHERE id = ?",
		claims.UserID,
	).Scan(&username, &role, &disabledAt)
	if err != nil {
		return nil, err
	}
	if disabledAt.Valid {
		return nil, errUserDisabled
	}
	if role == "" {
		role = claims.Role
	}

	refreshed := *claims
	refreshed.Username = username
	refreshed.Role = role
	return &refreshed, nil
}

func (s *Server) isSetupRequired() (bool, error) {
	var count int
	if err := s.db.Conn().QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return false, err
	}
	return count == 0, nil
}

func (s *Server) ensureSessionActive(w http.ResponseWriter, claims *auth.Claims) (*auth.Claims, error) {
	lastActive := sessionLastActive(claims)
	if !lastActive.IsZero() && time.Since(lastActive) > sessionIdleTimeout {
		return nil, errSessionExpired
	}
	if lastActive.IsZero() {
		lastActive = time.Now()
	}
	if time.Since(lastActive) >= sessionRefreshInterval {
		updated := time.Now()
		token, err := s.auth.GenerateTokenWithLastActive(claims.UserID, claims.Username, claims.Role, updated)
		if err != nil {
			return nil, err
		}
		auth.SetSessionCookie(w, token)
		refreshed := *claims
		refreshed.LastActive = updated.Unix()
		return &refreshed, nil
	}
	return claims, nil
}

func sessionLastActive(claims *auth.Claims) time.Time {
	if claims == nil {
		return time.Time{}
	}
	if claims.LastActive > 0 {
		return time.Unix(claims.LastActive, 0)
	}
	if claims.IssuedAt != nil {
		return claims.IssuedAt.Time
	}
	return time.Time{}
}

func (s *Server) passwordPolicyError(password, username string) string {
	trimmed := strings.TrimSpace(password)
	if trimmed == "" {
		return "Password is required."
	}
	if len([]rune(trimmed)) < passwordMinLength {
		return fmt.Sprintf("Password must be at least %d characters.", passwordMinLength)
	}
	if len([]rune(trimmed)) > passwordMaxLength {
		return fmt.Sprintf("Password must be at most %d characters.", passwordMaxLength)
	}
	lower := strings.ToLower(trimmed)
	if strings.TrimSpace(username) != "" {
		if strings.Contains(lower, strings.ToLower(username)) {
			return "Password cannot contain your username."
		}
	}
	appName := strings.TrimSpace(s.config.App.Name)
	if appName == "" {
		appName = "blocks"
	}
	if strings.Contains(lower, strings.ToLower(appName)) {
		return "Password cannot contain the app name."
	}
	return ""
}

func (s *Server) setupRoutes() {
	s.router.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(s.staticFS))))
	s.router.Get("/media/sets/{id}/image", s.handleSetImageProxy)
	s.router.Get("/", s.handleHome)
	s.router.Get("/setup", s.handleSetupPage)
	s.router.Post("/setup", s.handleSetupCreate)
	s.router.Get("/login", s.handleLoginPage)
	s.router.Post("/login", s.handleLogin)
	s.router.Post("/logout", s.handleLogout)
	s.router.Get("/profile", s.handleProfilePage)
	s.router.Post("/profile/password", s.handleProfilePassword)
	s.router.Post("/profile/disable", s.handleProfileDisable)
	s.router.Post("/profile/api-tokens", s.handleProfileAPITokenCreate)
	s.router.Post("/profile/api-tokens/{id}/revoke", s.handleProfileAPITokenRevoke)
	s.router.Post("/profile/api-tokens/clear-warning", s.handleDismissAPITokensWarning)
	s.router.Get("/brands", s.handleBrandsPage)
	s.router.Post("/brands", s.handleCreateBrandForm)
	s.router.Post("/brands/{id}/update", s.handleUpdateBrandForm)
	s.router.Post("/brands/{id}/delete", s.handleDeleteBrandForm)
	s.router.Get("/sets/new", s.handleSetForm)
	s.router.Get("/sets/{id}/edit", s.handleSetForm)
	s.router.Get("/brands/new", s.handleBrandForm)
	s.router.Get("/brands/{id}/edit", s.handleBrandForm)
	s.router.Get("/brands/{id}", s.handleBrandDetail)
	s.router.Get("/sets", s.handleSetsPage)
	s.router.Post("/sets", s.handleCreateSetForm)
	s.router.Post("/sets/{id}/update", s.handleUpdateSetForm)
	s.router.Post("/sets/{id}/delete", s.handleDeleteSetForm)
	s.router.Get("/collection/new", s.handleCollectionForm)
	s.router.Get("/collection/{id}/edit", s.handleCollectionForm)
	s.router.Get("/collection", s.handleCollectionPage)
	s.router.Post("/collection", s.handleCreateCollectionForm)
	s.router.Post("/collection/{id}/update", s.handleUpdateCollectionForm)
	s.router.Post("/collection/{id}/delete", s.handleDeleteCollectionForm)
	s.router.Post("/collection/{id}/images", s.handleCollectionImageUpload)
	s.router.Post("/collection/{id}/images/{imageID}/delete", s.handleCollectionImageDelete)
	s.router.Get("/sets/{id}", s.handleSetDetail)
	s.router.Get("/import", s.handleImportPage)
	s.router.Post("/import/upload", s.handleImportUpload)
	s.router.Post("/import/confirm", s.handleImportConfirm)
	s.router.Get("/export", s.handleExportPage)
	s.router.Get("/export/rebrickable", s.handleExportRebrickable)
	s.router.Get("/export/brickset", s.handleExportBrickset)
	s.router.Get("/export/blocks", s.handleExportBlocks)
	s.router.Get("/media/collection/images/{id}", s.handleCollectionImageServe)

	s.router.Get("/admin/users", s.handleAdminUsersPage)
	s.router.Get("/admin/users/new", s.handleAdminUserForm)
	s.router.Get("/admin/users/{id}/edit", s.handleAdminUserForm)
	s.router.Post("/admin/users", s.handleAdminCreateUser)
	s.router.Post("/admin/users/{id}/update", s.handleAdminUpdateUser)
	s.router.Post("/admin/users/{id}/delete", s.handleAdminDeleteUser)
	s.router.Post("/admin/users/{id}/disable", s.handleAdminDisableUser)
	s.router.Post("/admin/users/{id}/enable", s.handleAdminEnableUser)
	s.router.Post("/admin/users/{id}/api-tokens/{tokenID}/revoke", s.handleAdminRevokeUserToken)

	s.router.Route("/api", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Post("/login", s.handleAPILogin)
			r.Post("/logout", s.handleAPILogout)
			r.Get("/ping", s.handleAPIPing)
		})

		r.Route("/users", func(r chi.Router) {
			r.Get("/", s.handleAPIListUsers)
			r.Post("/", s.handleAPICreateUser)
			r.Put("/{id}", s.handleAPIUpdateUser)
			r.Post("/{id}/disable", s.handleAPIDisableUser)
			r.Post("/{id}/enable", s.handleAPIEnableUser)
			r.Delete("/{id}", s.handleAPIDeleteUser)
		})

		r.Route("/brands", func(r chi.Router) {
			r.Get("/", s.handleListBrands)
			r.Post("/", s.handleCreateBrand)
			r.Get("/{id}", s.handleGetBrand)
			r.Put("/{id}", s.handleUpdateBrand)
			r.Delete("/{id}", s.handleDeleteBrand)
		})

		r.Route("/sets", func(r chi.Router) {
			r.Get("/", s.handleListSets)
			r.Post("/", s.handleCreateSet)
			r.Get("/{id}", s.handleGetSet)
			r.Put("/{id}", s.handleUpdateSet)
			r.Delete("/{id}", s.handleDeleteSet)
		})

		r.Route("/collection", func(r chi.Router) {
			r.Get("/", s.handleListCollection)
			r.Post("/", s.handleCreateCollectionItem)
			r.Put("/{id}", s.handleUpdateCollectionItem)
			r.Delete("/{id}", s.handleDeleteCollectionItem)
		})

		r.Route("/tags", func(r chi.Router) {
			r.Get("/", s.handleListTags)
		})

		r.Route("/valuations", func(r chi.Router) {
			r.Post("/sets/{id}/refresh", s.handleRefreshValuation)
		})

		r.Route("/providers", func(r chi.Router) {
			r.Get("/sets/{setNum}", s.handleFetchSetMetadata)
		})
	})

	s.router.NotFound(s.handleNotFound)
	s.router.MethodNotAllowed(s.handleMethodNotAllowed)
}

type PageData struct {
	Title   string
	Data    interface{}
	Message string
	Error   string
}

type collectionImageView struct {
	Image     models.CollectionItemImage
	ItemID    int64
	Condition models.ItemCondition
	Status    models.ItemStatus
}

func (s *Server) renderTemplate(w http.ResponseWriter, r *http.Request, tmplName string, data interface{}) {
	w.Header().Set("Content-Type", "text/html")

	user, loggedIn := currentUser(r)
	pageTitle := "Blocks"
	if dataMap, ok := data.(map[string]interface{}); ok {
		if title, ok := dataMap["Title"].(string); ok && title != "" {
			pageTitle = title
		}
	}

	tmplData := map[string]interface{}{
		"Title":                 pageTitle,
		"isLoggedIn":            loggedIn,
		"Version":               version.Version,
		"CSRFToken":             s.csrfTokenForRequest(w, r),
		"SessionIdleSeconds":    int(sessionIdleTimeout.Seconds()),
		"SessionWarningSeconds": int((5 * time.Minute).Seconds()),
	}
	if loggedIn {
		tmplData["role"] = normalizeRole(user.Role)
	}
	if s.apiTokensRevokedAt != nil {
		if !loggedIn {
			tmplData["APITokensRevokedAt"] = s.apiTokensRevokedAt.Format("Jan 2, 2006 15:04 MST")
		} else if showWarning, err := s.shouldShowAPITokensWarning(user.UserID); err != nil {
			log.Printf("warning check failed: %v", err)
			tmplData["APITokensRevokedAt"] = s.apiTokensRevokedAt.Format("Jan 2, 2006 15:04 MST")
		} else if showWarning {
			tmplData["APITokensRevokedAt"] = s.apiTokensRevokedAt.Format("Jan 2, 2006 15:04 MST")
		}
	}

	if tmplName != "login.html" && tmplName != "error.html" && tmplName != "setup.html" && !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if dataMap, ok := data.(map[string]interface{}); ok {
		for key, value := range dataMap {
			tmplData[key] = value
		}
	} else if data != nil {
		tmplData["Data"] = data
	}
	if tmplName == "profile.html" {
		if _, ok := tmplData["FlashClass"]; !ok {
			tmplData["FlashClass"] = "flash-block"
		}
	}

	tmpl, ok := s.templates[tmplName]
	if !ok {
		// #nosec G706 -- log only, no sensitive sink.
		log.Printf("Template not found: %s", tmplName)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, tmplName, tmplData); err != nil {
		// #nosec G706 -- log only, no sensitive sink.
		log.Printf("Error rendering template %s: %v", tmplName, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	w.WriteHeader(status)
	s.renderTemplate(w, r, "error.html", map[string]interface{}{
		"Title":        title,
		"ErrorTitle":   title,
		"ErrorMessage": message,
		"Status":       status,
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		if err := json.NewEncoder(w).Encode(map[string]string{"error": "not_found"}); err != nil {
			log.Printf("encode not_found response: %v", err)
		}
		return
	}

	s.renderError(w, r, http.StatusNotFound, "Page Not Found", "We couldn't find the page you're looking for.")
}

func (s *Server) handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		if err := json.NewEncoder(w).Encode(map[string]string{"error": "method_not_allowed"}); err != nil {
			log.Printf("encode method_not_allowed response: %v", err)
		}
		return
	}

	s.renderError(w, r, http.StatusMethodNotAllowed, "Method Not Allowed", "That action isn't supported for this page.")
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				stack := string(debug.Stack())
				log.Printf("panic: %v\n%s", err, stack)
				if strings.HasPrefix(r.URL.Path, "/api") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					if err := json.NewEncoder(w).Encode(map[string]string{"error": "internal_server_error"}); err != nil {
						log.Printf("encode internal_server_error response: %v", err)
					}
					return
				}
				message := "We hit an unexpected error. Please try again."
				data := map[string]interface{}{
					"Title":        "Something Went Wrong",
					"ErrorTitle":   "Something Went Wrong",
					"ErrorMessage": message,
					"Status":       http.StatusInternalServerError,
				}
				if os.Getenv("BLOCKS_ENV") == "development" {
					data["ErrorDetails"] = fmt.Sprintf("%v\n\n%s", err, stack)
				}
				w.WriteHeader(http.StatusInternalServerError)
				s.renderTemplate(w, r, "error.html", data)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

func (s *Server) roleMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy, ok := rolePolicyForRequest(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		user, loggedIn := currentUser(r)
		if !loggedIn {
			respondUnauthorized(w, r)
			return
		}

		role := normalizeRole(user.Role)
		if !roleAllowed(role, policy...) {
			// #nosec G706 -- log only, no sensitive sink.
			log.Printf("forbidden request: role=%s method=%s path=%s", role, r.Method, r.URL.Path)
			respondForbidden(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	stats := s.getDashboardStats()
	recentItems := s.getRecentCollectionItems()
	themeInsights := s.getCollectionThemeInsights()
	tagInsights := s.getCollectionTagInsights()
	brandInsights := s.getSetsByBrandInsights()

	data := map[string]interface{}{
		"Title":         "Dashboard",
		"Stats":         stats,
		"RecentItems":   recentItems,
		"ThemeInsights": themeInsights,
		"TagInsights":   tagInsights,
		"BrandInsights": brandInsights,
	}
	addFlashFromQuery(r, data)

	s.renderTemplate(w, r, "dashboard.html", data)
}

func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	setupRequired, err := s.isSetupRequired()
	if err != nil {
		http.Error(w, "Unable to check setup", http.StatusInternalServerError)
		return
	}
	data := map[string]interface{}{
		"Title":         "Setup",
		"SetupComplete": !setupRequired,
	}
	addFlashFromQuery(r, data)
	s.renderTemplate(w, r, "setup.html", data)
}

func (s *Server) handleSetupCreate(w http.ResponseWriter, r *http.Request) {
	setupRequired, err := s.isSetupRequired()
	if err != nil {
		http.Error(w, "Unable to check setup", http.StatusInternalServerError)
		return
	}
	if !setupRequired {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderTemplate(w, r, "setup.html", map[string]interface{}{
			"Title": "Setup",
			"Error": "Invalid form submission. Please try again.",
		})
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")

	if username == "" || password == "" {
		s.renderTemplate(w, r, "setup.html", map[string]interface{}{
			"Title":    "Setup",
			"Error":    "Username and password are required.",
			"Username": username,
		})
		return
	}
	if password != confirm {
		s.renderTemplate(w, r, "setup.html", map[string]interface{}{
			"Title":    "Setup",
			"Error":    "Passwords do not match.",
			"Username": username,
		})
		return
	}
	if errMsg := s.passwordPolicyError(password, username); errMsg != "" {
		s.renderTemplate(w, r, "setup.html", map[string]interface{}{
			"Title":    "Setup",
			"Error":    errMsg,
			"Username": username,
		})
		return
	}

	var count int
	if err := s.db.Conn().QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		http.Error(w, "Unable to check setup", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	hash, err := s.hashPassword(password)
	if err != nil {
		s.renderTemplate(w, r, "setup.html", map[string]interface{}{
			"Title":    "Setup",
			"Error":    "Unable to create user right now.",
			"Username": username,
		})
		return
	}

	_, err = s.db.Conn().Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		username,
		hash,
		models.RoleAdmin,
	)
	if err != nil {
		s.renderTemplate(w, r, "setup.html", map[string]interface{}{
			"Title":    "Setup",
			"Error":    "Unable to create user right now.",
			"Username": username,
		})
		return
	}

	var userID int64
	if err := s.db.Conn().QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID); err != nil {
		s.renderTemplate(w, r, "setup.html", map[string]interface{}{
			"Title": "Setup",
			"Error": "Unable to sign in right now.",
		})
		return
	}

	token, err := s.auth.GenerateToken(userID, username, string(models.RoleAdmin))
	if err != nil {
		s.renderTemplate(w, r, "setup.html", map[string]interface{}{
			"Title": "Setup",
			"Error": "Unable to sign in right now.",
		})
		return
	}
	auth.SetSessionCookie(w, token)
	s.issueCSRFCookie(w)

	redirectWithMessage(w, r, "/", "Setup complete. Welcome!")
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if setupRequired, err := s.isSetupRequired(); err == nil && setupRequired {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if r.Context().Value(userContextKey) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"Title": "Sign in",
	}
	addFlashFromQuery(r, data)
	s.renderTemplate(w, r, "login.html", data)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if setupRequired, err := s.isSetupRequired(); err == nil && setupRequired {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderTemplate(w, r, "login.html", map[string]interface{}{
			"Error": "Invalid form submission. Please try again.",
		})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var userID int64
	var passwordHash string
	var role string
	var disabledAt sql.NullString

	err := s.db.Conn().QueryRow(
		"SELECT id, password_hash, role, disabled_at FROM users WHERE username = ?",
		username,
	).Scan(&userID, &passwordHash, &role, &disabledAt)

	if err != nil {
		if err == sql.ErrNoRows {
			s.renderTemplate(w, r, "login.html", map[string]interface{}{
				"Error": "Invalid username or password.",
			})
			return
		}
		s.renderTemplate(w, r, "login.html", map[string]interface{}{
			"Error": "Unable to sign in right now. Please try again.",
		})
		return
	}

	if err := s.auth.CheckPassword(password, passwordHash); err != nil {
		s.renderTemplate(w, r, "login.html", map[string]interface{}{
			"Error": "Invalid username or password.",
		})
		return
	}
	if disabledAt.Valid {
		s.renderTemplate(w, r, "login.html", map[string]interface{}{
			"Error": "Your account is disabled.",
		})
		return
	}

	role, err = s.ensureSingleUserAdmin(userID, role)
	if err != nil {
		s.renderTemplate(w, r, "login.html", map[string]interface{}{
			"Error": "Unable to sign in right now. Please try again.",
		})
		return
	}

	if role == "" {
		role = string(models.RoleAdmin)
	}

	token, err := s.auth.GenerateToken(userID, username, role)
	if err != nil {
		s.renderTemplate(w, r, "login.html", map[string]interface{}{
			"Error": "Failed to sign in. Please try again.",
		})
		return
	}

	auth.SetSessionCookie(w, token)
	s.issueCSRFCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	auth.ClearSessionCookie(w)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secureCookieEnabled(),
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// #nosec G101 -- settings keys are not credentials.
const appSettingSessionSecretFingerprint = "session_secret_fingerprint"

// #nosec G101 -- settings keys are not credentials.
const appSettingAPITokensRevokedAt = "api_tokens_revoked_at"

// #nosec G101 -- settings keys are not credentials.
const appSettingAPITokensWarningDismissedPrefix = "api_tokens_warning_dismissed_user_"

func ensureSessionSecretFingerprint(conn *sql.DB, secret string) (*time.Time, error) {
	fingerprint := sessionSecretFingerprint(secret)
	var stored string
	err := conn.QueryRow("SELECT value FROM app_settings WHERE key = ?", appSettingSessionSecretFingerprint).Scan(&stored)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if err := upsertAppSetting(conn, appSettingSessionSecretFingerprint, fingerprint); err != nil {
				return nil, err
			}
			return loadAPITokensRevokedAt(conn)
		}
		return nil, err
	}
	if stored == fingerprint {
		return loadAPITokensRevokedAt(conn)
	}

	tx, err := conn.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	revokedAt := time.Now().UTC()
	if _, err := tx.Exec("UPDATE api_tokens SET revoked_at = ? WHERE revoked_at IS NULL", revokedAt); err != nil {
		return nil, err
	}
	if err := upsertAppSetting(tx, appSettingSessionSecretFingerprint, fingerprint); err != nil {
		return nil, err
	}
	if err := upsertAppSetting(tx, appSettingAPITokensRevokedAt, revokedAt.Format(time.RFC3339)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &revokedAt, nil
}

func loadAPITokensRevokedAt(conn *sql.DB) (*time.Time, error) {
	var value string
	err := conn.QueryRow("SELECT value FROM app_settings WHERE key = ?", appSettingAPITokensRevokedAt).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return nil, nil
	}
	return &parsed, nil
}

func apiTokensWarningDismissKey(userID int64) string {
	return fmt.Sprintf("%s%d", appSettingAPITokensWarningDismissedPrefix, userID)
}

func (s *Server) shouldShowAPITokensWarning(userID int64) (bool, error) {
	if s.apiTokensRevokedAt == nil {
		return false, nil
	}
	var value string
	err := s.db.Conn().QueryRow("SELECT value FROM app_settings WHERE key = ?", apiTokensWarningDismissKey(userID)).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil
		}
		return true, err
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return true, nil
	}
	return parsed.Before(*s.apiTokensRevokedAt), nil
}

func upsertAppSetting(execer interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, key, value string) error {
	_, err := execer.Exec(
		"INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
		key,
		value,
	)
	return err
}

func sessionSecretFingerprint(secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("blocks/session-secret"))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) handleAPILogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"` // #nosec G117 -- request payload field.
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var userID int64
	var passwordHash string
	var role string
	var disabledAt sql.NullString

	err := s.db.Conn().QueryRow(
		"SELECT id, password_hash, role, disabled_at FROM users WHERE username = ?",
		req.Username,
	).Scan(&userID, &passwordHash, &role, &disabledAt)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		if encodeErr := json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"}); encodeErr != nil {
			log.Printf("encode invalid credentials response: %v", encodeErr)
		}
		return
	}

	if err := s.auth.CheckPassword(req.Password, passwordHash); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		if encodeErr := json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"}); encodeErr != nil {
			log.Printf("encode invalid credentials response: %v", encodeErr)
		}
		return
	}
	if disabledAt.Valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if encodeErr := json.NewEncoder(w).Encode(map[string]string{"error": "account_disabled"}); encodeErr != nil {
			log.Printf("encode account disabled response: %v", encodeErr)
		}
		return
	}

	role, err = s.ensureSingleUserAdmin(userID, role)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		if encodeErr := json.NewEncoder(w).Encode(map[string]string{"error": "Unable to sign in"}); encodeErr != nil {
			log.Printf("encode sign in error response: %v", encodeErr)
		}
		return
	}

	if role == "" {
		role = string(models.RoleAdmin)
	}

	token, err := s.auth.GenerateToken(userID, req.Username, role)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"token": token}); err != nil {
		log.Printf("encode token response: %v", err)
	}
}

func (s *Server) handleAPILogout(w http.ResponseWriter, r *http.Request) {
	auth.ClearSessionCookie(w)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAPIPing(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleImportPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":            "Import",
		"Conditions":       []models.ItemCondition{models.ConditionSealed, models.ConditionOpen, models.ConditionPartial, models.ConditionCustom},
		"Statuses":         []models.ItemStatus{models.StatusActive, models.StatusSold, models.StatusDonated},
		"DefaultCondition": models.ConditionOpen,
		"DefaultStatus":    models.StatusActive,
	}
	addFlashFromQuery(r, data)
	if user, ok := currentUser(r); ok {
		data["role"] = normalizeRole(user.Role)
	}
	if _, ok := data["role"]; !ok {
		data["role"] = models.RoleViewer
	}
	data["CurrentYear"] = time.Now().Year()

	s.renderTemplate(w, r, "import.html", data)
}

func (s *Server) handleImportUpload(w http.ResponseWriter, r *http.Request) {
	maxSize := s.config.Uploads.MaxSize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024
	}
	if strings.TrimSpace(r.Header.Get("Content-Type")) == "" {
		redirectWithError(w, r, "/import", "Missing upload content")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSize)
	if err := r.ParseMultipartForm(maxSize); err != nil {
		redirectWithError(w, r, "/import", "Unable to read upload")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		redirectWithError(w, r, "/import", "CSV file is required")
		return
	}
	defer func() {
		_ = file.Close()
	}()

	condition := models.ItemCondition(strings.TrimSpace(r.FormValue("condition")))
	if condition == "" {
		condition = models.ConditionOpen
	}
	if !condition.Valid() {
		redirectWithError(w, r, "/import", "Invalid condition selection")
		return
	}

	status := models.ItemStatus(strings.TrimSpace(r.FormValue("status")))
	if status == "" {
		status = models.StatusActive
	}
	if !status.Valid() {
		redirectWithError(w, r, "/import", "Invalid status selection")
		return
	}

	token, err := generateImportToken()
	if err != nil {
		redirectWithError(w, r, "/import", "Unable to prepare import")
		return
	}
	importKey := path.Join("imports", token+".csv")
	if err := s.uploads.Save(r.Context(), importKey, file); err != nil {
		redirectWithError(w, r, "/import", "Unable to save import file")
		return
	}
	importReader, err := s.uploads.Open(r.Context(), importKey)
	if err != nil {
		_ = s.uploads.Delete(r.Context(), importKey)
		redirectWithError(w, r, "/import", "Unable to read import file")
		return
	}
	rows, warnings, err := parseCollectionCSV(importReader)
	_ = importReader.Close()
	if err != nil {
		_ = s.uploads.Delete(r.Context(), importKey)
		redirectWithError(w, r, "/import", err.Error())
		return
	}
	if len(rows) == 0 {
		_ = s.uploads.Delete(r.Context(), importKey)
		redirectWithError(w, r, "/import", "No rows found in CSV")
		return
	}

	legoBrandID, err := s.findLegoBrandID()
	if err != nil {
		_ = s.uploads.Delete(r.Context(), importKey)
		redirectWithError(w, r, "/import", err.Error())
		return
	}

	preview, err := s.buildImportPreview(rows, legoBrandID, condition, status, warnings)
	if err != nil {
		_ = s.uploads.Delete(r.Context(), importKey)
		redirectWithError(w, r, "/import", "Unable to build import preview")
		return
	}
	preview.Token = token

	data := map[string]interface{}{
		"Title":       "Import Preview",
		"Preview":     preview,
		"Condition":   condition,
		"Status":      status,
		"ImportToken": token,
	}
	addFlashFromQuery(r, data)

	s.renderTemplate(w, r, "import_preview.html", data)
}

func (s *Server) handleImportConfirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		redirectWithError(w, r, "/import", "Unable to read import confirmation")
		return
	}

	token := strings.TrimSpace(r.FormValue("token"))
	if token == "" {
		redirectWithError(w, r, "/import", "Missing import token")
		return
	}

	importKey := path.Join("imports", token+".csv")
	importReader, err := s.uploads.Open(r.Context(), importKey)
	if err != nil {
		redirectWithError(w, r, "/import", "Import file not found")
		return
	}
	defer func() {
		_ = importReader.Close()
	}()

	condition := models.ItemCondition(strings.TrimSpace(r.FormValue("condition")))
	if condition == "" {
		condition = models.ConditionOpen
	}
	if !condition.Valid() {
		redirectWithError(w, r, "/import", "Invalid condition selection")
		return
	}

	status := models.ItemStatus(strings.TrimSpace(r.FormValue("status")))
	if status == "" {
		status = models.StatusActive
	}
	if !status.Valid() {
		redirectWithError(w, r, "/import", "Invalid status selection")
		return
	}

	rows, warnings, err := parseCollectionCSV(importReader)
	if err != nil {
		redirectWithError(w, r, "/import", err.Error())
		return
	}
	if len(rows) == 0 {
		redirectWithError(w, r, "/import", "No rows found in CSV")
		return
	}

	legoBrandID, err := s.findLegoBrandID()
	if err != nil {
		redirectWithError(w, r, "/import", err.Error())
		return
	}

	tx, err := s.db.Conn().Begin()
	if err != nil {
		redirectWithError(w, r, "/import", "Unable to start import")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	overrides := parseImportOverrides(r.Form)
	result := &importResult{
		Condition: condition,
		Status:    status,
		Warnings:  warnings,
	}

	for _, row := range rows {
		setNumber := normalizeSetCode(row.SetNumber)
		if setNumber == "" || row.Quantity < 1 {
			result.Skipped++
			continue
		}

		setID, found, err := findSetByCodeTx(tx, legoBrandID, setNumber)
		if err != nil {
			redirectWithError(w, r, "/import", "Unable to read sets during import")
			return
		}
		if !found {
			set := s.buildSetFromMetadata(r.Context(), legoBrandID, setNumber)
			setID, err = createSetTx(tx, set)
			if err != nil {
				redirectWithError(w, r, "/import", "Unable to create set during import")
				return
			}
			result.CreatedSets++
		}

		itemID, existingQty, err := findCollectionItemTx(tx, setID, condition, status)
		if err != nil {
			redirectWithError(w, r, "/import", "Unable to read collection items")
			return
		}

		override := overrides[setNumber]
		if override.Action == "skip" {
			result.Skipped++
			result.Rows = append(result.Rows, importResultRow{
				SetNumber: setNumber,
				Quantity:  row.Quantity,
				Action:    "skipped",
				Note:      "Skipped by override",
			})
			continue
		}

		importQty := row.Quantity
		if override.Quantity > 0 {
			importQty = override.Quantity
		}
		if itemID != 0 {
			if importQty > existingQty {
				if err := updateCollectionItemQuantityTx(tx, itemID, importQty); err != nil {
					redirectWithError(w, r, "/import", "Unable to update collection items")
					return
				}
				result.UpdatedItems++
				result.Rows = append(result.Rows, importResultRow{
					SetNumber: setNumber,
					Quantity:  importQty,
					Action:    "updated",
					Note:      fmt.Sprintf("Updated from %d", existingQty),
				})
			} else {
				result.Skipped++
				result.Rows = append(result.Rows, importResultRow{
					SetNumber: setNumber,
					Quantity:  importQty,
					Action:    "skipped",
					Note:      fmt.Sprintf("Existing quantity %d is higher", existingQty),
				})
			}
			continue
		}
		if err := insertCollectionItemTx(tx, setID, importQty, condition, status); err != nil {
			redirectWithError(w, r, "/import", "Unable to insert collection items")
			return
		}
		result.CreatedItems++
		result.Rows = append(result.Rows, importResultRow{
			SetNumber: setNumber,
			Quantity:  importQty,
			Action:    "created",
			Note:      "Added new collection item",
		})
	}

	if err := tx.Commit(); err != nil {
		redirectWithError(w, r, "/import", "Unable to complete import")
		return
	}
	_ = s.uploads.Delete(r.Context(), importKey)

	data := map[string]interface{}{
		"Title":  "Import Results",
		"Result": result,
	}
	addFlashFromQuery(r, data)
	if user, ok := currentUser(r); ok {
		data["role"] = normalizeRole(user.Role)
	}
	s.renderTemplate(w, r, "import_result.html", data)
}

func (s *Server) handleProfilePage(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data := s.profileData(user)
	addFlashFromQuery(r, data)

	s.renderTemplate(w, r, "profile.html", data)
}

func (s *Server) profileData(user *auth.Claims) map[string]interface{} {
	data := map[string]interface{}{
		"Title":     "Profile",
		"Username":  user.Username,
		"Role":      normalizeRole(user.Role),
		"APITokens": s.listUserAPITokens(user.UserID),
	}
	return data
}

func (s *Server) handleProfileAPITokenCreate(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		data := s.profileData(user)
		data["Error"] = "Invalid form submission."
		s.renderTemplate(w, r, "profile.html", data)
		return
	}

	name := strings.TrimSpace(r.FormValue("token_name"))
	scope := strings.TrimSpace(r.FormValue("scope"))
	if scope == "" {
		scope = apiTokenScopeRead
	}
	if scope != apiTokenScopeRead && scope != apiTokenScopeWrite && scope != apiTokenScopeAdmin {
		data := s.profileData(user)
		data["Error"] = "Invalid API token scope."
		s.renderTemplate(w, r, "profile.html", data)
		return
	}
	if scope == apiTokenScopeAdmin && normalizeRole(user.Role) != models.RoleAdmin {
		data := s.profileData(user)
		data["Error"] = "Admin scope requires an admin role."
		s.renderTemplate(w, r, "profile.html", data)
		return
	}

	token, err := s.createAPIToken(user.UserID, name, scope)
	if err != nil {
		data := s.profileData(user)
		data["Error"] = "Unable to create API token right now."
		s.renderTemplate(w, r, "profile.html", data)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	data := s.profileData(user)
	data["Message"] = "API token created. Copy it now."
	data["NewAPIToken"] = token
	data["NewAPITokenScope"] = scope
	if name != "" {
		data["NewAPITokenName"] = name
	}
	s.renderTemplate(w, r, "profile.html", data)
}

func (s *Server) handleProfileAPITokenRevoke(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectWithError(w, r, "/profile", "Invalid request.")
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		redirectWithError(w, r, "/profile", "Invalid token ID.")
		return
	}

	result, err := s.db.Conn().Exec(
		"UPDATE api_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
		id,
		user.UserID,
	)
	if err != nil {
		redirectWithError(w, r, "/profile", "Unable to revoke token.")
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		redirectWithError(w, r, "/profile", "Token not found.")
		return
	}
	redirectWithMessage(w, r, "/profile", "API token revoked.")
}

func (s *Server) handleDismissAPITokensWarning(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectWithError(w, r, "/profile", "Invalid request.")
		return
	}
	if s.apiTokensRevokedAt == nil {
		redirectWithMessage(w, r, "/profile", "API token warning cleared.")
		return
	}
	key := apiTokensWarningDismissKey(user.UserID)
	if err := upsertAppSetting(s.db.Conn(), key, time.Now().UTC().Format(time.RFC3339)); err != nil {
		redirectWithError(w, r, "/profile", "Unable to clear token warning.")
		return
	}
	redirectWithMessage(w, r, "/profile", "API token warning cleared.")
}

func (s *Server) handleExportPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "Export",
	}
	addFlashFromQuery(r, data)
	if user, ok := currentUser(r); ok {
		data["role"] = normalizeRole(user.Role)
	}
	s.renderTemplate(w, r, "export.html", data)
}

func (s *Server) handleExportRebrickable(w http.ResponseWriter, r *http.Request) {
	items, err := s.getCollectionItemsForExport()
	if err != nil {
		redirectWithError(w, r, "/export", "Unable to export collection")
		return
	}

	filename := fmt.Sprintf("rebrickable_export_%s.csv", time.Now().Format("20060102"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))

	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"Set Number", "Quantity", "Inventory Ver"})
	for _, item := range items {
		row := []string{
			item.SetCode,
			strconv.Itoa(item.Quantity),
			"1",
		}
		_ = writer.Write(row)
	}
	writer.Flush()
}

func (s *Server) handleExportBrickset(w http.ResponseWriter, r *http.Request) {
	items, err := s.getCollectionItemsForExport()
	if err != nil {
		redirectWithError(w, r, "/export", "Unable to export collection")
		return
	}

	filename := fmt.Sprintf("brickset_export_%s.csv", time.Now().Format("20060102"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))

	writer := csv.NewWriter(w)
	_ = writer.Write([]string{
		"SetID", "Number", "Variant", "YearFrom", "Category", "Theme", "ThemeGroup", "Subtheme", "SetName",
		"Image", "ImageFilename", "USRetailPrice", "UKRetailPrice", "CARetailPrice", "DERetailPrice",
		"USDateAdded", "USDateRemoved", "Pieces", "Minifigs", "MinifigNumbers", "PackagingType", "Availability",
		"USItemNumber", "EUItemNumber", "EAN", "UPC", "Width", "Height", "Depth", "Weight",
		"ModelDimension1", "ModelDimension2", "ModelDimension3", "AgeMin", "AgeMax", "OwnCount", "WantCount",
		"InstructionsCount", "AdditionalImageCount", "Released", "Rating", "BrickLinkSoldPriceNew", "BrickLinkSoldPriceUsed",
		"Designers", "LaunchDate", "ExitDate", "Own", "Want", "QtyOwned", "QtyOwnedNew", "QtyOwnedUsed",
		"QtyWanted", "WantedPriority", "", "Flag2", "Flag3", "Flag4", "Flag5", "Flag6", "Flag7", "Flag8", "UserNotes",
	})

	for _, item := range items {
		year := ""
		if item.Year != nil {
			year = strconv.Itoa(*item.Year)
		}
		pieces := ""
		if item.PieceCount != nil {
			pieces = strconv.Itoa(*item.PieceCount)
		}
		theme := ""
		if item.Theme != nil {
			theme = *item.Theme
		}
		row := []string{
			"", item.SetCode, "1", year, "Normal", theme, "", "", item.Name,
			"", "", "", "", "", "",
			"", "", pieces, "", "", "", "",
			"", "", "", "", "", "", "", "",
			"", "", "", "", "", strconv.Itoa(item.Quantity), "",
			"", "", "", "", "", "",
			"", "", "X", "", strconv.Itoa(item.Quantity), "0",
			"", "", "", "", "", "", "", "",
		}
		_ = writer.Write(row)
	}

	writer.Flush()
}

func (s *Server) handleExportBlocks(w http.ResponseWriter, r *http.Request) {
	if format := strings.TrimSpace(r.URL.Query().Get("format")); format == "sqlite" {
		path := s.config.Database.Path
		if path == "" {
			redirectWithError(w, r, "/export", "Database path not configured")
			return
		}
		root, err := os.OpenRoot(filepath.Dir(path))
		if err != nil {
			redirectWithError(w, r, "/export", "Unable to export database")
			return
		}
		defer func() {
			if err := root.Close(); err != nil {
				log.Printf("closing export root: %v", err)
			}
		}()
		file, err := root.Open(filepath.Base(path))
		if err != nil {
			redirectWithError(w, r, "/export", "Unable to export database")
			return
		}
		defer func() {
			if err := file.Close(); err != nil {
				log.Printf("closing export file: %v", err)
			}
		}()

		filename := fmt.Sprintf("blocks_export_%s.db", time.Now().Format("20060102"))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		_, _ = io.Copy(w, file)
		return
	}

	items, err := s.getCollectionItemsForExport()
	if err != nil {
		redirectWithError(w, r, "/export", "Unable to export collection")
		return
	}

	filename := fmt.Sprintf("blocks_export_%s.csv", time.Now().Format("20060102"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"Set Code", "Name", "Quantity", "Condition", "Status", "Theme", "Year", "Piece Count"})
	for _, item := range items {
		year := ""
		if item.Year != nil {
			year = strconv.Itoa(*item.Year)
		}
		pieces := ""
		if item.PieceCount != nil {
			pieces = strconv.Itoa(*item.PieceCount)
		}
		theme := ""
		if item.Theme != nil {
			theme = *item.Theme
		}
		row := []string{item.SetCode, item.Name, strconv.Itoa(item.Quantity), string(item.Condition), string(item.Status), theme, year, pieces}
		_ = writer.Write(row)
	}
	writer.Flush()
}

type rebrickableImportRow struct {
	SetNumber string
	Quantity  int
}

type importPreview struct {
	Rows         []importPreviewRow
	TotalRows    int
	CreatedSets  int
	CreatedItems int
	UpdatedItems int
	SkippedItems int
	Warnings     []string
	Token        string
	Condition    models.ItemCondition
	Status       models.ItemStatus
}

type importPreviewRow struct {
	SetNumber   string
	Quantity    int
	ExistingQty int
	Action      string
	Note        string
}

type importResult struct {
	Rows         []importResultRow
	CreatedSets  int
	CreatedItems int
	UpdatedItems int
	Skipped      int
	Warnings     []string
	Condition    models.ItemCondition
	Status       models.ItemStatus
}

type importResultRow struct {
	SetNumber string
	Quantity  int
	Action    string
	Note      string
}

type exportCollectionRow struct {
	SetCode    string
	Name       string
	Quantity   int
	Condition  models.ItemCondition
	Status     models.ItemStatus
	Theme      *string
	Year       *int
	PieceCount *int
}

func parseCollectionCSV(reader io.Reader) ([]rebrickableImportRow, []string, error) {
	csvReader := csv.NewReader(reader)
	csvReader.TrimLeadingSpace = true

	header, err := csvReader.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read CSV header")
	}

	setIndex := -1
	qtyIndex := -1
	qtyOwnedNewIndex := -1
	qtyOwnedUsedIndex := -1
	for idx, col := range header {
		name := normalizeHeader(col)
		switch name {
		case "set number", "set num", "set", "number":
			setIndex = idx
		case "qtyowned", "qty owned", "quantity", "qty", "owncount":
			if qtyIndex == -1 {
				qtyIndex = idx
			}
		case "qtyownednew", "qty owned new":
			qtyOwnedNewIndex = idx
		case "qtyownedused", "qty owned used":
			qtyOwnedUsedIndex = idx
		}
	}

	if setIndex == -1 || (qtyIndex == -1 && qtyOwnedNewIndex == -1 && qtyOwnedUsedIndex == -1) {
		return nil, nil, fmt.Errorf("CSV must include a set number column and quantity values (QtyOwned/Quantity/OwnCount)")
	}

	rowsBySet := make(map[string]int)
	var warnings []string
	rowNumber := 1
	validRows := 0
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read CSV rows")
		}
		rowNumber++
		if len(record) == 0 {
			continue
		}
		setNumber := strings.TrimSpace(getColumn(record, setIndex))
		quantity := parseQuantity(record, qtyIndex, qtyOwnedNewIndex, qtyOwnedUsedIndex)
		if setNumber == "" || quantity <= 0 {
			warnings = append(warnings, fmt.Sprintf("Skipped row %d due to missing set number or quantity", rowNumber))
			continue
		}
		setNumber = normalizeSetCode(setNumber)
		rowsBySet[setNumber] += quantity
		validRows++
	}

	rows := make([]rebrickableImportRow, 0, len(rowsBySet))
	for setNumber, quantity := range rowsBySet {
		rows = append(rows, rebrickableImportRow{SetNumber: setNumber, Quantity: quantity})
	}
	if len(rowsBySet) < validRows {
		warnings = append(warnings, "Duplicate set numbers were combined")
	}

	return rows, warnings, nil
}

func generateCSRFToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	issuedAt := strconv.FormatInt(time.Now().Unix(), 10)
	return "v1." + issuedAt + "." + hex.EncodeToString(buffer), nil
}

func secureCookieEnabled() bool {
	return os.Getenv("BLOCKS_ENV") == "production"
}

func generateImportToken() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func generateUploadToken() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func detectImageContentType(file multipart.File) (string, error) {
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("unable to read image")
	}
	contentType := http.DetectContentType(buffer[:n])
	if imageExtension(contentType) == "" {
		return "", fmt.Errorf("unsupported image type")
	}
	return contentType, nil
}

func (s *Server) saveCollectionItemImages(ctx context.Context, itemID int64, files []*multipart.FileHeader) error {
	if len(files) == 0 {
		return nil
	}

	maxSize := s.config.Uploads.MaxSize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024
	}

	tx, err := s.db.Conn().Begin()
	if err != nil {
		return fmt.Errorf("unable to save images")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var storedKeys []string
	for _, header := range files {
		if header.Size > maxSize {
			cleanupStoredImages(ctx, s.uploads, storedKeys)
			return fmt.Errorf("one or more images are too large")
		}

		file, err := header.Open()
		if err != nil {
			cleanupStoredImages(ctx, s.uploads, storedKeys)
			return fmt.Errorf("unable to read image")
		}

		contentType, err := detectImageContentType(file)
		if err != nil {
			_ = file.Close()
			cleanupStoredImages(ctx, s.uploads, storedKeys)
			return err
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			_ = file.Close()
			cleanupStoredImages(ctx, s.uploads, storedKeys)
			return fmt.Errorf("unable to read image")
		}

		ext := imageExtension(contentType)
		if ext == "" {
			_ = file.Close()
			cleanupStoredImages(ctx, s.uploads, storedKeys)
			return fmt.Errorf("unsupported image type")
		}

		token, err := generateUploadToken()
		if err != nil {
			_ = file.Close()
			cleanupStoredImages(ctx, s.uploads, storedKeys)
			return fmt.Errorf("unable to prepare image upload")
		}
		key := path.Join("collection", strconv.FormatInt(itemID, 10), token+ext)
		if err := s.uploads.Save(ctx, key, file); err != nil {
			_ = file.Close()
			cleanupStoredImages(ctx, s.uploads, storedKeys)
			return fmt.Errorf("unable to save image")
		}
		_ = file.Close()
		storedKeys = append(storedKeys, key)

		if _, err := tx.Exec(
			"INSERT INTO collection_item_images (collection_item_id, storage_key, content_type) VALUES (?, ?, ?)",
			itemID, key, contentType,
		); err != nil {
			cleanupStoredImages(ctx, s.uploads, storedKeys)
			return fmt.Errorf("unable to save image")
		}
	}

	if err := tx.Commit(); err != nil {
		cleanupStoredImages(ctx, s.uploads, storedKeys)
		return fmt.Errorf("unable to save images")
	}

	return nil
}

func cleanupStoredImages(ctx context.Context, storage uploads.Storage, keys []string) {
	for _, key := range keys {
		_ = storage.Delete(ctx, key)
	}
}

func (s *Server) buildImportPreview(rows []rebrickableImportRow, brandID int64, condition models.ItemCondition, status models.ItemStatus, warnings []string) (*importPreview, error) {
	preview := &importPreview{
		TotalRows: len(rows),
		Warnings:  warnings,
		Condition: condition,
		Status:    status,
	}

	for _, row := range rows {
		setNumber := normalizeSetCode(row.SetNumber)
		if setNumber == "" || row.Quantity < 1 {
			preview.SkippedItems++
			preview.Rows = append(preview.Rows, importPreviewRow{
				SetNumber: setNumber,
				Quantity:  row.Quantity,
				Action:    "skipped",
				Note:      "Invalid row",
			})
			continue
		}

		setID, found, err := findSetByCode(s.db.Conn(), brandID, setNumber)
		if err != nil {
			return nil, err
		}
		if !found {
			preview.CreatedSets++
			preview.CreatedItems++
			preview.Rows = append(preview.Rows, importPreviewRow{
				SetNumber: setNumber,
				Quantity:  row.Quantity,
				Action:    "create",
				Note:      "Set not found; will create set and collection item",
			})
			continue
		}

		itemID, existingQty, err := findCollectionItem(s.db.Conn(), setID, condition, status)
		if err != nil {
			return nil, err
		}
		if itemID == 0 {
			preview.CreatedItems++
			preview.Rows = append(preview.Rows, importPreviewRow{
				SetNumber: setNumber,
				Quantity:  row.Quantity,
				Action:    "create",
				Note:      "Collection item will be added",
			})
			continue
		}

		if row.Quantity > existingQty {
			preview.UpdatedItems++
			preview.Rows = append(preview.Rows, importPreviewRow{
				SetNumber:   setNumber,
				Quantity:    row.Quantity,
				ExistingQty: existingQty,
				Action:      "update",
				Note:        fmt.Sprintf("Will update from %d", existingQty),
			})
		} else {
			preview.SkippedItems++
			preview.Rows = append(preview.Rows, importPreviewRow{
				SetNumber:   setNumber,
				Quantity:    row.Quantity,
				ExistingQty: existingQty,
				Action:      "skip",
				Note:        "Existing quantity is higher or equal",
			})
		}
	}

	return preview, nil
}

func findSetByCode(conn *sql.DB, brandID int64, setNumber string) (int64, bool, error) {
	var id int64
	err := conn.QueryRow("SELECT id FROM sets WHERE brand_id = ? AND set_code = ?", brandID, setNumber).Scan(&id)
	if err == nil {
		return id, true, nil
	}
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	return 0, false, err
}

func findCollectionItem(conn *sql.DB, setID int64, condition models.ItemCondition, status models.ItemStatus) (int64, int, error) {
	var id int64
	var quantity int
	err := conn.QueryRow(
		"SELECT id, quantity FROM collection_items WHERE set_id = ? AND condition = ? AND status = ? LIMIT 1",
		setID, condition, status,
	).Scan(&id, &quantity)
	if err == nil {
		return id, quantity, nil
	}
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return 0, 0, err
}

func (s *Server) getCollectionItemsForExport() ([]exportCollectionRow, error) {
	rows, err := s.db.Conn().Query(`
		SELECT s.set_code, s.name, s.theme, s.year, s.piece_count,
		       ci.quantity, ci.condition, ci.status
		FROM collection_items ci
		JOIN sets s ON s.id = ci.set_id
		ORDER BY s.set_code
	`)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("closing export rows: %v", err)
		}
	}()

	var items []exportCollectionRow
	for rows.Next() {
		var item exportCollectionRow
		if err := rows.Scan(
			&item.SetCode, &item.Name, &item.Theme, &item.Year, &item.PieceCount,
			&item.Quantity, &item.Condition, &item.Status,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func parseQuantity(record []string, qtyIndex, qtyOwnedNewIndex, qtyOwnedUsedIndex int) int {
	if qtyIndex >= 0 {
		qtyValue := strings.TrimSpace(getColumn(record, qtyIndex))
		if qtyValue != "" {
			if quantity, err := strconv.Atoi(qtyValue); err == nil {
				return quantity
			}
		}
	}

	quantity := 0
	if qtyOwnedNewIndex >= 0 {
		qtyValue := strings.TrimSpace(getColumn(record, qtyOwnedNewIndex))
		if qtyValue != "" {
			if parsed, err := strconv.Atoi(qtyValue); err == nil {
				quantity += parsed
			}
		}
	}
	if qtyOwnedUsedIndex >= 0 {
		qtyValue := strings.TrimSpace(getColumn(record, qtyOwnedUsedIndex))
		if qtyValue != "" {
			if parsed, err := strconv.Atoi(qtyValue); err == nil {
				quantity += parsed
			}
		}
	}

	return quantity
}

type importOverride struct {
	Action   string
	Quantity int
}

func parseImportOverrides(values url.Values) map[string]importOverride {
	overrides := make(map[string]importOverride)
	for key, vals := range values {
		if strings.HasPrefix(key, "action_") {
			setNumber := strings.TrimPrefix(key, "action_")
			if setNumber == "" || len(vals) == 0 {
				continue
			}
			entry := overrides[setNumber]
			entry.Action = strings.TrimSpace(vals[0])
			overrides[setNumber] = entry
			continue
		}
		if strings.HasPrefix(key, "override_") {
			setNumber := strings.TrimPrefix(key, "override_")
			if setNumber == "" || len(vals) == 0 {
				continue
			}
			value := strings.TrimSpace(vals[0])
			if value == "" {
				continue
			}
			qty, err := strconv.Atoi(value)
			if err != nil {
				continue
			}
			entry := overrides[setNumber]
			entry.Quantity = qty
			overrides[setNumber] = entry
		}
	}

	return overrides
}

func normalizeHeader(value string) string {
	value = strings.TrimPrefix(value, "\ufeff")
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", " ")
	return strings.Join(strings.Fields(value), " ")
}

func getColumn(record []string, index int) string {
	if index < 0 || index >= len(record) {
		return ""
	}
	return record[index]
}

func (s *Server) findLegoBrandID() (int64, error) {
	brands := s.getAllBrands()
	if len(brands) == 0 {
		return 0, fmt.Errorf("no brands found; create a LEGO brand first")
	}
	for _, brand := range brands {
		if brand.Kind == models.BrandKindLEGO {
			return brand.ID, nil
		}
	}
	return 0, fmt.Errorf("no LEGO brand found; create one to import Rebrickable exports")
}

func (s *Server) buildSetFromMetadata(ctx context.Context, brandID int64, setNumber string) *models.Set {
	set := &models.Set{
		BrandID: brandID,
		SetCode: setNumber,
		Name:    setNumber,
	}
	metadata, err := s.fetchSetMetadata(ctx, setNumber)
	if err != nil {
		return set
	}

	if name := getString(metadata, "name"); name != "" {
		set.Name = name
	}
	if year := getInt(metadata, "year"); year > 0 {
		set.Year = &year
	}
	if pieces := getInt(metadata, "piece_count"); pieces > 0 {
		set.PieceCount = &pieces
	}
	if theme := getString(metadata, "theme"); theme != "" {
		set.Theme = &theme
	}
	if imageURL := getString(metadata, "image_url"); imageURL != "" {
		set.ImageURL = &imageURL
	}

	return set
}

func findSetByCodeTx(tx *sql.Tx, brandID int64, setNumber string) (int64, bool, error) {
	var id int64
	err := tx.QueryRow("SELECT id FROM sets WHERE brand_id = ? AND set_code = ?", brandID, setNumber).Scan(&id)
	if err == nil {
		return id, true, nil
	}
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	return 0, false, err
}

func createSetTx(tx *sql.Tx, set *models.Set) (int64, error) {
	result, err := tx.Exec(
		"INSERT INTO sets (brand_id, set_code, name, year, piece_count, minifigs, theme, image_url, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		set.BrandID, set.SetCode, set.Name, set.Year, set.PieceCount, set.Minifigs, set.Theme, set.ImageURL, set.Notes,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func findCollectionItemTx(tx *sql.Tx, setID int64, condition models.ItemCondition, status models.ItemStatus) (int64, int, error) {
	var id int64
	var quantity int
	err := tx.QueryRow(
		"SELECT id, quantity FROM collection_items WHERE set_id = ? AND condition = ? AND status = ? LIMIT 1",
		setID, condition, status,
	).Scan(&id, &quantity)
	if err == nil {
		return id, quantity, nil
	}
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return 0, 0, err
}

func updateCollectionItemQuantityTx(tx *sql.Tx, id int64, quantity int) error {
	_, err := tx.Exec("UPDATE collection_items SET quantity = ? WHERE id = ?", quantity, id)
	return err
}

func insertCollectionItemTx(tx *sql.Tx, setID int64, quantity int, condition models.ItemCondition, status models.ItemStatus) error {
	_, err := tx.Exec(
		"INSERT INTO collection_items (set_id, quantity, condition, status) VALUES (?, ?, ?, ?)",
		setID, quantity, condition, status,
	)
	return err
}

func normalizeSetCode(setNumber string) string {
	trimmed := strings.TrimSpace(setNumber)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "-") {
		return trimmed
	}
	return trimmed + "-1"
}

func getString(values map[string]interface{}, key string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", value))
	}
}

func getInt(values map[string]interface{}, key string) int {
	value, ok := values[key]
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil {
			return 0
		}
		return parsed
	default:
		parsed, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", value)))
		if err != nil {
			return 0
		}
		return parsed
	}
}

func (s *Server) handleProfilePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		data := s.profileData(user)
		data["Error"] = "Invalid form submission."
		s.renderTemplate(w, r, "profile.html", data)
		return
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")
	if newPassword == "" || confirmPassword == "" {
		data := s.profileData(user)
		data["Error"] = "New password fields are required."
		s.renderTemplate(w, r, "profile.html", data)
		return
	}
	if newPassword != confirmPassword {
		data := s.profileData(user)
		data["Error"] = "New passwords do not match."
		s.renderTemplate(w, r, "profile.html", data)
		return
	}
	if errMsg := s.passwordPolicyError(newPassword, user.Username); errMsg != "" {
		data := s.profileData(user)
		data["Error"] = errMsg
		s.renderTemplate(w, r, "profile.html", data)
		return
	}

	var passwordHash string
	err := s.db.Conn().QueryRow("SELECT password_hash FROM users WHERE id = ?", user.UserID).Scan(&passwordHash)
	if err != nil {
		data := s.profileData(user)
		data["Error"] = "Unable to update password right now."
		s.renderTemplate(w, r, "profile.html", data)
		return
	}

	if err := s.auth.CheckPassword(currentPassword, passwordHash); err != nil {
		data := s.profileData(user)
		data["Error"] = "Current password is incorrect."
		s.renderTemplate(w, r, "profile.html", data)
		return
	}

	newHash, err := s.hashPassword(newPassword)
	if err != nil {
		data := s.profileData(user)
		data["Error"] = "Unable to update password right now."
		s.renderTemplate(w, r, "profile.html", data)
		return
	}

	if _, err := s.db.Conn().Exec("UPDATE users SET password_hash = ? WHERE id = ?", newHash, user.UserID); err != nil {
		data := s.profileData(user)
		data["Error"] = "Unable to update password right now."
		s.renderTemplate(w, r, "profile.html", data)
		return
	}

	data := s.profileData(user)
	data["Message"] = "Password updated successfully."
	s.renderTemplate(w, r, "profile.html", data)
}

func (s *Server) handleProfileDisable(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := s.disableUser(user.UserID); err != nil {
		data := s.profileData(user)
		data["Error"] = "Unable to disable your account right now."
		s.renderTemplate(w, r, "profile.html", data)
		return
	}

	auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleAdminUsersPage(w http.ResponseWriter, r *http.Request) {
	users := s.listUsers()
	data := map[string]interface{}{
		"Title": "Users",
		"Users": users,
	}
	addFlashFromQuery(r, data)

	s.renderTemplate(w, r, "admin_users.html", data)
}

func (s *Server) handleAdminUserForm(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "User",
	}
	addFlashFromQuery(r, data)
	if idStr := chi.URLParam(r, "id"); idStr != "" {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid ID", http.StatusBadRequest)
			return
		}
		user, err := s.getUserByID(id)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		data["User"] = user
		data["APITokens"] = s.listUserAPITokens(user.ID)
	}

	s.renderTemplate(w, r, "admin_user_form.html", data)
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderTemplate(w, r, "admin_user_form.html", map[string]interface{}{
			"Error": "Invalid form submission.",
		})
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	role := normalizeRole(r.FormValue("role"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")

	if username == "" || password == "" {
		s.renderTemplate(w, r, "admin_user_form.html", map[string]interface{}{
			"Error": "Username and password are required.",
			"User":  &models.User{Username: username, Role: role},
		})
		return
	}
	if password != confirm {
		s.renderTemplate(w, r, "admin_user_form.html", map[string]interface{}{
			"Error": "Passwords do not match.",
			"User":  &models.User{Username: username, Role: role},
		})
		return
	}
	if errMsg := s.passwordPolicyError(password, username); errMsg != "" {
		s.renderTemplate(w, r, "admin_user_form.html", map[string]interface{}{
			"Error": errMsg,
			"User":  &models.User{Username: username, Role: role},
		})
		return
	}

	hash, err := s.hashPassword(password)
	if err != nil {
		s.renderTemplate(w, r, "admin_user_form.html", map[string]interface{}{
			"Error": "Unable to create user right now.",
			"User":  &models.User{Username: username, Role: role},
		})
		return
	}

	if _, err := s.db.Conn().Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", username, hash, role); err != nil {
		s.renderTemplate(w, r, "admin_user_form.html", map[string]interface{}{
			"Error": "Unable to create user right now.",
			"User":  &models.User{Username: username, Role: role},
		})
		return
	}

	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (s *Server) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	user, err := s.getUserByID(id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	role := normalizeRole(r.FormValue("role"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")

	updateViewUser := &models.User{
		ID:         id,
		Username:   username,
		Role:       role,
		DisabledAt: user.DisabledAt,
		CreatedAt:  user.CreatedAt,
	}

	if username == "" {
		s.renderTemplate(w, r, "admin_user_form.html", map[string]interface{}{
			"Error": "Username is required.",
			"User":  updateViewUser,
		})
		return
	}
	if err := s.ensureCanChangeRole(id, normalizeRole(user.Role.String()), role); err != nil {
		s.renderTemplate(w, r, "admin_user_form.html", map[string]interface{}{
			"Error": err.Error(),
			"User":  updateViewUser,
		})
		return
	}
	if password != "" && password != confirm {
		s.renderTemplate(w, r, "admin_user_form.html", map[string]interface{}{
			"Error": "Passwords do not match.",
			"User":  updateViewUser,
		})
		return
	}
	if password != "" {
		if errMsg := s.passwordPolicyError(password, username); errMsg != "" {
			s.renderTemplate(w, r, "admin_user_form.html", map[string]interface{}{
				"Error": errMsg,
				"User":  updateViewUser,
			})
			return
		}
	}

	_, err = s.db.Conn().Exec("UPDATE users SET username = ?, role = ? WHERE id = ?", username, role, id)
	if err != nil {
		s.renderTemplate(w, r, "admin_user_form.html", map[string]interface{}{
			"Error": "Unable to update user right now.",
			"User":  updateViewUser,
		})
		return
	}

	if password != "" {
		hash, err := s.hashPassword(password)
		if err != nil {
			s.renderTemplate(w, r, "admin_user_form.html", map[string]interface{}{
				"Error": "Unable to update user password right now.",
				"User":  updateViewUser,
			})
			return
		}
		if _, err := s.db.Conn().Exec("UPDATE users SET password_hash = ? WHERE id = ?", hash, id); err != nil {
			s.renderTemplate(w, r, "admin_user_form.html", map[string]interface{}{
				"Error": "Unable to update user password right now.",
				"User":  updateViewUser,
			})
			return
		}
	}

	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	user, ok := currentUser(r)
	if ok && user.UserID == id {
		s.redirectAdminUsersError(w, r, "Cannot delete your own account")
		return
	}

	if err := s.ensureCanRemoveUser(id); err != nil {
		s.redirectAdminUsersError(w, r, err.Error())
		return
	}

	if _, err := s.db.Conn().Exec("DELETE FROM users WHERE id = ?", id); err != nil {
		s.redirectAdminUsersError(w, r, "Unable to delete user right now.")
		return
	}

	s.redirectAdminUsersMessage(w, r, "User deleted.")
}

func (s *Server) handleAdminDisableUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := s.ensureCanRemoveUser(id); err != nil {
		s.redirectAdminUsersError(w, r, err.Error())
		return
	}

	if err := s.disableUser(id); err != nil {
		s.redirectAdminUsersError(w, r, "Unable to disable user right now.")
		return
	}

	s.redirectAdminUsersMessage(w, r, "User disabled.")
}

func (s *Server) handleAdminEnableUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if _, err := s.db.Conn().Exec("UPDATE users SET disabled_at = NULL WHERE id = ?", id); err != nil {
		s.redirectAdminUsersError(w, r, "Unable to enable user right now.")
		return
	}

	s.redirectAdminUsersMessage(w, r, "User enabled.")
}

func (s *Server) handleAdminRevokeUserToken(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		redirectWithError(w, r, "/admin/users", "Invalid user ID.")
		return
	}
	if _, err := s.getUserByID(userID); err != nil {
		redirectWithError(w, r, "/admin/users", "User not found.")
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectWithError(w, r, fmt.Sprintf("/admin/users/%d/edit", userID), "Invalid request.")
		return
	}

	tokenID, err := strconv.ParseInt(chi.URLParam(r, "tokenID"), 10, 64)
	if err != nil {
		redirectWithError(w, r, fmt.Sprintf("/admin/users/%d/edit", userID), "Invalid token ID.")
		return
	}

	result, err := s.db.Conn().Exec(
		"UPDATE api_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
		tokenID,
		userID,
	)
	if err != nil {
		redirectWithError(w, r, fmt.Sprintf("/admin/users/%d/edit", userID), "Unable to revoke token.")
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		redirectWithError(w, r, fmt.Sprintf("/admin/users/%d/edit", userID), "Token not found.")
		return
	}
	redirectWithMessage(w, r, fmt.Sprintf("/admin/users/%d/edit", userID), "API token revoked.")
}

func (s *Server) handleBrandsPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":  "Brands",
		"Brands": s.getAllBrands(),
	}
	addFlashFromQuery(r, data)

	s.renderTemplate(w, r, "brands.html", data)
}

func (s *Server) handleListTags(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	query = strings.ToLower(query)

	var rows *sql.Rows
	var err error
	if query == "" {
		rows, err = s.db.Conn().Query("SELECT name FROM tags ORDER BY name LIMIT 20")
	} else {
		rows, err = s.db.Conn().Query("SELECT name FROM tags WHERE name LIKE ? ORDER BY name LIMIT 20", query+"%")
	}
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		if encodeErr := json.NewEncoder(w).Encode(map[string]string{"error": "database_error"}); encodeErr != nil {
			log.Printf("encode database_error response: %v", encodeErr)
		}
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("closing tag rows: %v", err)
		}
	}()

	var tags []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		tags = append(tags, name)
	}
	if tags == nil {
		tags = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tags); err != nil {
		log.Printf("encode tags response: %v", err)
	}
}

func (s *Server) handleSetsPage(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	theme := strings.TrimSpace(r.URL.Query().Get("theme"))
	tagsInput := strings.TrimSpace(r.URL.Query().Get("tags"))
	filterTags := parseTagInput(tagsInput)
	brandIDStr := strings.TrimSpace(r.URL.Query().Get("brand"))
	var brandID int64
	if brandIDStr != "" {
		parsedID, err := strconv.ParseInt(brandIDStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid brand", http.StatusBadRequest)
			return
		}
		brandID = parsedID
	}

	filtered := s.getFilteredSets(search, theme, filterTags, brandID)

	data := map[string]interface{}{
		"Title":          "Sets",
		"Sets":           filtered,
		"Brands":         s.getAllBrands(),
		"Search":         search,
		"Theme":          theme,
		"TagInput":       tagsInput,
		"TagPlaceholder": "tag, tag",
		"BrandID":        brandID,
	}
	addFlashFromQuery(r, data)

	s.renderTemplate(w, r, "sets.html", data)
}

func (s *Server) buildSetFormData(title string, set *models.Set, tagInput string) map[string]interface{} {
	data := map[string]interface{}{
		"Title":                title,
		"Set":                  set,
		"TagInput":             tagInput,
		"Brands":               s.getAllBrands(),
		"CurrentYear":          time.Now().Year(),
		"BricksetEnabled":      strings.TrimSpace(s.config.Providers.Brickset.APIKey) != "",
		"RebrickableEnabled":   strings.TrimSpace(s.config.Providers.Rebrickable.APIKey) != "",
		"MetadataFetchEnabled": true,
	}
	return data
}

func (s *Server) handleCollectionPage(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	condition := strings.TrimSpace(r.URL.Query().Get("condition"))
	tagsInput := strings.TrimSpace(r.URL.Query().Get("tags"))
	filterTags := parseTagInput(tagsInput)

	filtered := s.getFilteredCollectionItems(status, condition, filterTags)

	data := map[string]interface{}{
		"Title":     "Collection",
		"Items":     filtered,
		"Status":    status,
		"Condition": condition,
		"TagInput":  tagsInput,
		"Currency":  s.config.App.DefaultCurrency,
	}
	addFlashFromQuery(r, data)

	s.renderTemplate(w, r, "collection.html", data)
}

func (s *Server) handleCreateBrandForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderTemplate(w, r, "brand_form.html", map[string]interface{}{
			"Error": "Invalid form submission.",
			"Brand": &models.Brand{},
		})
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	kind := models.BrandKind(strings.TrimSpace(r.FormValue("kind")))
	notes := parseOptionalString(r.FormValue("notes"))

	if name == "" || !kind.Valid() {
		s.renderTemplate(w, r, "brand_form.html", map[string]interface{}{
			"Error": "Please provide a name and valid brand kind.",
			"Brand": &models.Brand{Name: name, Kind: kind, Notes: notes},
		})
		return
	}

	_, err := s.db.Conn().Exec(
		"INSERT INTO brands (name, kind, notes) VALUES (?, ?, ?)",
		name, kind, notes,
	)
	if err != nil {
		s.renderTemplate(w, r, "brand_form.html", map[string]interface{}{
			"Error": "Unable to create brand. Please try again.",
			"Brand": &models.Brand{Name: name, Kind: kind, Notes: notes},
		})
		return
	}

	redirectWithMessage(w, r, "/brands", "Brand created.")
}

func (s *Server) handleUpdateBrandForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderTemplate(w, r, "brand_form.html", map[string]interface{}{
			"Error": "Invalid form submission.",
		})
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	kind := models.BrandKind(strings.TrimSpace(r.FormValue("kind")))
	notes := parseOptionalString(r.FormValue("notes"))

	if name == "" || !kind.Valid() {
		s.renderTemplate(w, r, "brand_form.html", map[string]interface{}{
			"Error": "Please provide a name and valid brand kind.",
			"Brand": &models.Brand{ID: id, Name: name, Kind: kind, Notes: notes},
		})
		return
	}

	_, err = s.db.Conn().Exec(
		"UPDATE brands SET name = ?, kind = ?, notes = ? WHERE id = ?",
		name, kind, notes, id,
	)
	if err != nil {
		s.renderTemplate(w, r, "brand_form.html", map[string]interface{}{
			"Error": "Unable to update brand. Please try again.",
			"Brand": &models.Brand{ID: id, Name: name, Kind: kind, Notes: notes},
		})
		return
	}

	redirectWithMessage(w, r, "/brands", "Brand updated.")
}

func (s *Server) handleDeleteBrandForm(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if _, err := s.db.Conn().Exec("DELETE FROM brands WHERE id = ?", id); err != nil {
		redirectWithError(w, r, "/brands", "Unable to delete brand right now.")
		return
	}

	redirectWithMessage(w, r, "/brands", "Brand deleted.")
}

func (s *Server) handleCreateSetForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		data := s.buildSetFormData("New Set", &models.Set{}, "")
		data["Error"] = "Invalid form submission."
		s.renderTemplate(w, r, "set_form.html", data)
		return
	}

	tagsInput := r.FormValue("tags")
	tags := parseTagInput(tagsInput)

	set, err := parseSetForm(r)
	if err != nil {
		data := s.buildSetFormData("New Set", set, tagsInput)
		data["Error"] = err.Error()
		s.renderTemplate(w, r, "set_form.html", data)
		return
	}

	tx, err := s.db.Conn().Begin()
	if err != nil {
		data := s.buildSetFormData("New Set", set, tagsInput)
		data["Error"] = "Unable to create set. Please try again."
		s.renderTemplate(w, r, "set_form.html", data)
		return
	}

	result, err := tx.Exec(
		"INSERT INTO sets (brand_id, set_code, name, year, piece_count, minifigs, theme, image_url, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		set.BrandID, set.SetCode, set.Name, set.Year, set.PieceCount, set.Minifigs,
		set.Theme, set.ImageURL, set.Notes,
	)
	if err != nil {
		_ = tx.Rollback()
		data := s.buildSetFormData("New Set", set, tagsInput)
		data["Error"] = "Unable to create set. Please try again."
		s.renderTemplate(w, r, "set_form.html", data)
		return
	}

	setID, err := result.LastInsertId()
	if err != nil {
		_ = tx.Rollback()
		data := s.buildSetFormData("New Set", set, tagsInput)
		data["Error"] = "Unable to create set. Please try again."
		s.renderTemplate(w, r, "set_form.html", data)
		return
	}

	if err := s.replaceSetTags(tx, setID, tags); err != nil {
		_ = tx.Rollback()
		data := s.buildSetFormData("New Set", set, tagsInput)
		data["Error"] = "Unable to save tags. Please try again."
		s.renderTemplate(w, r, "set_form.html", data)
		return
	}

	if err := tx.Commit(); err != nil {
		data := s.buildSetFormData("New Set", set, tagsInput)
		data["Error"] = "Unable to create set. Please try again."
		s.renderTemplate(w, r, "set_form.html", data)
		return
	}

	redirectWithMessage(w, r, fmt.Sprintf("/sets/%d", setID), "Set created.")
}

func (s *Server) handleUpdateSetForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		id, idErr := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if idErr != nil {
			http.Error(w, "Invalid ID", http.StatusBadRequest)
			return
		}

		set, loadErr := s.getSetByID(id)
		if loadErr != nil {
			http.Error(w, "Set not found", http.StatusNotFound)
			return
		}

		data := s.buildSetFormData("Edit Set", set, strings.Join(set.Tags, ", "))
		data["Error"] = "Invalid form submission."
		s.renderTemplate(w, r, "set_form.html", data)
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	set, err := parseSetForm(r)
	if err != nil {
		set.ID = id
		data := s.buildSetFormData("Edit Set", set, r.FormValue("tags"))
		data["Error"] = err.Error()
		s.renderTemplate(w, r, "set_form.html", data)
		return
	}

	tagsInput := r.FormValue("tags")
	tags := parseTagInput(tagsInput)

	tx, err := s.db.Conn().Begin()
	if err != nil {
		set.ID = id
		data := s.buildSetFormData("Edit Set", set, tagsInput)
		data["Error"] = "Unable to update set. Please try again."
		s.renderTemplate(w, r, "set_form.html", data)
		return
	}

	_, err = tx.Exec(
		"UPDATE sets SET brand_id = ?, set_code = ?, name = ?, year = ?, piece_count = ?, minifigs = ?, theme = ?, image_url = ?, notes = ? WHERE id = ?",
		set.BrandID, set.SetCode, set.Name, set.Year, set.PieceCount, set.Minifigs,
		set.Theme, set.ImageURL, set.Notes, id,
	)
	if err != nil {
		_ = tx.Rollback()
		set.ID = id
		data := s.buildSetFormData("Edit Set", set, tagsInput)
		data["Error"] = "Unable to update set. Please try again."
		s.renderTemplate(w, r, "set_form.html", data)
		return
	}

	if err := s.replaceSetTags(tx, id, tags); err != nil {
		_ = tx.Rollback()
		set.ID = id
		data := s.buildSetFormData("Edit Set", set, tagsInput)
		data["Error"] = "Unable to save tags. Please try again."
		s.renderTemplate(w, r, "set_form.html", data)
		return
	}

	if err := tx.Commit(); err != nil {
		set.ID = id
		data := s.buildSetFormData("Edit Set", set, tagsInput)
		data["Error"] = "Unable to update set. Please try again."
		s.renderTemplate(w, r, "set_form.html", data)
		return
	}

	redirectWithMessage(w, r, fmt.Sprintf("/sets/%d", id), "Set updated.")
}

func (s *Server) handleDeleteSetForm(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if _, err := s.db.Conn().Exec("DELETE FROM sets WHERE id = ?", id); err != nil {
		redirectWithError(w, r, "/sets", "Unable to delete set right now.")
		return
	}

	redirectWithMessage(w, r, "/sets", "Set deleted.")
}

func (s *Server) handleCreateCollectionForm(w http.ResponseWriter, r *http.Request) {
	maxSize := s.config.Uploads.MaxSize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)
	if err := r.ParseMultipartForm(maxSize); err != nil {
		s.renderTemplate(w, r, "collection_form.html", map[string]interface{}{
			"Error": "Invalid form submission.",
			"Item":  &models.CollectionItem{},
			"Sets":  s.getAllSets(),
		})
		return
	}

	tagsInput := r.FormValue("tags")
	tags := parseTagInput(tagsInput)

	item, err := parseCollectionForm(r)
	if err != nil {
		s.renderTemplate(w, r, "collection_form.html", map[string]interface{}{
			"Error":    err.Error(),
			"Item":     item,
			"TagInput": tagsInput,
			"Sets":     s.getAllSets(),
		})
		return
	}

	tx, err := s.db.Conn().Begin()
	if err != nil {
		s.renderTemplate(w, r, "collection_form.html", map[string]interface{}{
			"Error":    "Unable to create collection item. Please try again.",
			"Item":     item,
			"TagInput": tagsInput,
			"Sets":     s.getAllSets(),
		})
		return
	}

	result, err := tx.Exec(
		"INSERT INTO collection_items (set_id, quantity, condition, location, purchase_price, purchase_date, missing_notes, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		item.SetID, item.Quantity, item.Condition, item.Location, item.PurchasePrice, item.PurchaseDate, item.MissingNotes, item.Status,
	)
	if err != nil {
		_ = tx.Rollback()
		s.renderTemplate(w, r, "collection_form.html", map[string]interface{}{
			"Error":    "Unable to create collection item. Please try again.",
			"Item":     item,
			"TagInput": tagsInput,
			"Sets":     s.getAllSets(),
		})
		return
	}

	itemID, err := result.LastInsertId()
	if err != nil {
		_ = tx.Rollback()
		s.renderTemplate(w, r, "collection_form.html", map[string]interface{}{
			"Error":    "Unable to create collection item. Please try again.",
			"Item":     item,
			"TagInput": tagsInput,
			"Sets":     s.getAllSets(),
		})
		return
	}

	if err := s.replaceCollectionItemTags(tx, itemID, tags); err != nil {
		_ = tx.Rollback()
		s.renderTemplate(w, r, "collection_form.html", map[string]interface{}{
			"Error":    "Unable to save tags. Please try again.",
			"Item":     item,
			"TagInput": tagsInput,
			"Sets":     s.getAllSets(),
		})
		return
	}

	if err := tx.Commit(); err != nil {
		s.renderTemplate(w, r, "collection_form.html", map[string]interface{}{
			"Error":    "Unable to create collection item. Please try again.",
			"Item":     item,
			"TagInput": tagsInput,
			"Sets":     s.getAllSets(),
		})
		return
	}

	var createFiles []*multipart.FileHeader
	if r.MultipartForm != nil {
		createFiles = r.MultipartForm.File["images"]
	}
	if err := s.saveCollectionItemImages(r.Context(), itemID, createFiles); err != nil {
		redirectWithError(w, r, fmt.Sprintf("/collection/%d/edit", itemID), err.Error())
		return
	}

	redirectWithMessage(w, r, "/collection", "Collection item created.")
}

func (s *Server) handleUpdateCollectionForm(w http.ResponseWriter, r *http.Request) {
	maxSize := s.config.Uploads.MaxSize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)
	if err := r.ParseMultipartForm(maxSize); err != nil {
		id, idErr := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if idErr != nil {
			http.Error(w, "Invalid ID", http.StatusBadRequest)
			return
		}

		item, loadErr := s.getCollectionItemByID(id)
		if loadErr != nil {
			http.Error(w, "Collection item not found", http.StatusNotFound)
			return
		}

		s.renderTemplate(w, r, "collection_form.html", map[string]interface{}{
			"Error": "Invalid form submission.",
			"Item":  item,
			"Sets":  s.getAllSets(),
		})
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	item, err := parseCollectionForm(r)
	if err != nil {
		item.ID = id
		s.renderTemplate(w, r, "collection_form.html", map[string]interface{}{
			"Error":    err.Error(),
			"Item":     item,
			"TagInput": r.FormValue("tags"),
			"Sets":     s.getAllSets(),
		})
		return
	}

	tagsInput := r.FormValue("tags")
	tags := parseTagInput(tagsInput)

	tx, err := s.db.Conn().Begin()
	if err != nil {
		item.ID = id
		s.renderTemplate(w, r, "collection_form.html", map[string]interface{}{
			"Error":    "Unable to update collection item. Please try again.",
			"Item":     item,
			"TagInput": tagsInput,
			"Sets":     s.getAllSets(),
		})
		return
	}

	_, err = tx.Exec(
		"UPDATE collection_items SET set_id = ?, quantity = ?, condition = ?, location = ?, purchase_price = ?, purchase_date = ?, missing_notes = ?, status = ? WHERE id = ?",
		item.SetID, item.Quantity, item.Condition, item.Location, item.PurchasePrice, item.PurchaseDate, item.MissingNotes, item.Status, id,
	)
	if err != nil {
		_ = tx.Rollback()
		item.ID = id
		s.renderTemplate(w, r, "collection_form.html", map[string]interface{}{
			"Error":    "Unable to update collection item. Please try again.",
			"Item":     item,
			"TagInput": tagsInput,
			"Sets":     s.getAllSets(),
		})
		return
	}

	if err := s.replaceCollectionItemTags(tx, id, tags); err != nil {
		_ = tx.Rollback()
		item.ID = id
		s.renderTemplate(w, r, "collection_form.html", map[string]interface{}{
			"Error":    "Unable to save tags. Please try again.",
			"Item":     item,
			"TagInput": tagsInput,
			"Sets":     s.getAllSets(),
		})
		return
	}

	if err := tx.Commit(); err != nil {
		item.ID = id
		s.renderTemplate(w, r, "collection_form.html", map[string]interface{}{
			"Error":    "Unable to update collection item. Please try again.",
			"Item":     item,
			"TagInput": tagsInput,
			"Sets":     s.getAllSets(),
		})
		return
	}

	var updateFiles []*multipart.FileHeader
	if r.MultipartForm != nil {
		updateFiles = r.MultipartForm.File["images"]
	}
	if err := s.saveCollectionItemImages(r.Context(), id, updateFiles); err != nil {
		redirectWithError(w, r, fmt.Sprintf("/collection/%d/edit", id), err.Error())
		return
	}

	redirectWithMessage(w, r, "/collection", "Collection item updated.")
}

func (s *Server) handleDeleteCollectionForm(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	images := s.getCollectionItemImages(id)
	for _, image := range images {
		if err := s.uploads.Delete(r.Context(), image.StorageKey); err != nil {
			// #nosec G706 -- log only, no sensitive sink.
			log.Printf("Unable to delete collection image %d: %v", image.ID, err)
		}
	}

	if _, err := s.db.Conn().Exec("DELETE FROM collection_items WHERE id = ?", id); err != nil {
		redirectWithError(w, r, "/collection", "Unable to delete collection item right now.")
		return
	}

	redirectWithMessage(w, r, "/collection", "Collection item deleted.")
}

func (s *Server) handleSetForm(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	var data map[string]interface{}

	if idStr != "" {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid ID", http.StatusBadRequest)
			return
		}

		set, err := s.getSetByID(id)
		if err != nil {
			http.Error(w, "Set not found", http.StatusNotFound)
			return
		}

		data = s.buildSetFormData("Edit Set", set, strings.Join(set.Tags, ", "))
	} else {
		data = s.buildSetFormData("New Set", &models.Set{}, "")
	}
	addFlashFromQuery(r, data)

	s.renderTemplate(w, r, "set_form.html", data)
}

func (s *Server) handleBrandForm(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	var data map[string]interface{}

	if idStr != "" {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid ID", http.StatusBadRequest)
			return
		}

		brand, err := s.getBrandByID(id)
		if err != nil {
			http.Error(w, "Brand not found", http.StatusNotFound)
			return
		}

		data = map[string]interface{}{
			"Title": "Edit Brand",
			"Brand": brand,
		}
	} else {
		data = map[string]interface{}{
			"Title": "New Brand",
			"Brand": &models.Brand{},
		}
	}
	addFlashFromQuery(r, data)

	s.renderTemplate(w, r, "brand_form.html", data)
}

func (s *Server) handleBrandDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	brand, err := s.getBrandByID(id)
	if err != nil {
		http.Error(w, "Brand not found", http.StatusNotFound)
		return
	}

	sets := s.getSetsByBrandID(id)

	data := map[string]interface{}{
		"Title": brand.Name,
		"Brand": brand,
		"Sets":  sets,
	}
	addFlashFromQuery(r, data)

	s.renderTemplate(w, r, "brand_detail.html", data)
}

func (s *Server) handleCollectionForm(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	setIDStr := r.URL.Query().Get("set_id")
	var data map[string]interface{}

	if idStr != "" {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid ID", http.StatusBadRequest)
			return
		}

		item, err := s.getCollectionItemByID(id)
		if err != nil {
			http.Error(w, "Collection item not found", http.StatusNotFound)
			return
		}

		data = map[string]interface{}{
			"Title":    "Edit Item",
			"Item":     item,
			"TagInput": strings.Join(item.Tags, ", "),
			"Sets":     s.getAllSets(),
		}
	} else {
		item := &models.CollectionItem{}
		data = map[string]interface{}{
			"Title":    "New Item",
			"Item":     item,
			"TagInput": "",
			"Sets":     s.getAllSets(),
		}
		if setIDStr != "" {
			if setID, err := strconv.ParseInt(setIDStr, 10, 64); err == nil {
				item.SetID = setID
			}
		}
	}
	addFlashFromQuery(r, data)

	s.renderTemplate(w, r, "collection_form.html", data)
}

func (s *Server) handleCollectionImageDelete(w http.ResponseWriter, r *http.Request) {
	itemID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	imageID, err := strconv.ParseInt(chi.URLParam(r, "imageID"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid image ID", http.StatusBadRequest)
		return
	}

	image, err := s.getCollectionItemImageByID(imageID)
	if err != nil {
		redirectWithError(w, r, fmt.Sprintf("/collection/%d/edit", itemID), "Image not found")
		return
	}
	if image.CollectionItemID != itemID {
		redirectWithError(w, r, fmt.Sprintf("/collection/%d/edit", itemID), "Image not found")
		return
	}

	if err := s.uploads.Delete(r.Context(), image.StorageKey); err != nil {
		redirectWithError(w, r, fmt.Sprintf("/collection/%d/edit", itemID), "Unable to delete image")
		return
	}

	if _, err := s.db.Conn().Exec("DELETE FROM collection_item_images WHERE id = ?", imageID); err != nil {
		redirectWithError(w, r, fmt.Sprintf("/collection/%d/edit", itemID), "Unable to delete image")
		return
	}

	redirectWithMessage(w, r, fmt.Sprintf("/collection/%d/edit", itemID), "Image deleted.")
}

func (s *Server) handleCollectionImageUpload(w http.ResponseWriter, r *http.Request) {
	itemID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	isAjax := strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest")

	if _, err := s.getCollectionItemByID(itemID); err != nil {
		// #nosec G706 -- log only, no sensitive sink.
		log.Printf("image upload: item %d not found: %v", itemID, err)
		if isAjax {
			respondJSON(w, http.StatusNotFound, map[string]string{"error": "collection item not found"})
			return
		}
		redirectWithError(w, r, "/collection", "Collection item not found")
		return
	}

	maxSize := s.config.Uploads.MaxSize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)
	if err := r.ParseMultipartForm(maxSize); err != nil {
		// #nosec G706 -- log only, no sensitive sink.
		log.Printf("image upload: parse multipart failed for item %d: %v", itemID, err)
		if isAjax {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "unable to read uploads"})
			return
		}
		redirectWithError(w, r, fmt.Sprintf("/collection/%d/edit", itemID), "Unable to read uploads")
		return
	}

	files := r.MultipartForm.File["images"]
	if len(files) == 0 {
		// #nosec G706 -- log only, no sensitive sink.
		log.Printf("image upload: no files provided for item %d", itemID)
		if isAjax {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "no images provided"})
			return
		}
		redirectWithError(w, r, fmt.Sprintf("/collection/%d/edit", itemID), "No images provided")
		return
	}

	if err := s.saveCollectionItemImages(r.Context(), itemID, files); err != nil {
		// #nosec G706 -- log only, no sensitive sink.
		log.Printf("image upload: save failed for item %d: %v", itemID, err)
		if isAjax {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		redirectWithError(w, r, fmt.Sprintf("/collection/%d/edit", itemID), err.Error())
		return
	}

	if isAjax {
		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	redirectWithMessage(w, r, fmt.Sprintf("/collection/%d/edit", itemID), "Images uploaded.")
}

func (s *Server) handleCollectionImageServe(w http.ResponseWriter, r *http.Request) {
	imageID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	image, err := s.getCollectionItemImageByID(imageID)
	if err != nil {
		http.Error(w, "Image not found", http.StatusNotFound)
		return
	}

	reader, err := s.uploads.Open(r.Context(), image.StorageKey)
	if err != nil {
		http.Error(w, "Image not found", http.StatusNotFound)
		return
	}
	defer func() {
		_ = reader.Close()
	}()

	contentType := strings.TrimSpace(image.ContentType)
	if contentType == "" {
		buffer := make([]byte, 512)
		n, _ := io.ReadFull(reader, buffer)
		contentType = http.DetectContentType(buffer[:n])
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if _, err := w.Write(buffer[:n]); err != nil {
			return
		}
		_, _ = io.Copy(w, reader)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = io.Copy(w, reader)
}

func (s *Server) handleSetDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	set, err := s.getSetByID(id)
	if err != nil {
		http.Error(w, "Set not found", http.StatusNotFound)
		return
	}

	valuations, _ := s.getValuationsForSet(id)
	collectionItems, _ := s.getCollectionItemsForSet(id)
	collectionImages := s.buildCollectionImageGallery(collectionItems)

	data := map[string]interface{}{
		"Title":            set.Name,
		"Set":              set,
		"Valuations":       valuations,
		"CollectionItems":  collectionItems,
		"CollectionImages": collectionImages,
		"ValuationEnabled": true,
	}
	addFlashFromQuery(r, data)

	s.renderTemplate(w, r, "set_detail.html", data)
}

func (s *Server) handleSetImageProxy(w http.ResponseWriter, r *http.Request) {
	setID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	set, err := s.getSetByID(setID)
	if err != nil {
		http.Error(w, "Set not found", http.StatusNotFound)
		return
	}

	cacheDir := filepath.Join("data", "cache", "set-images")
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		log.Printf("Unable to create image cache dir: %v", err)
	}

	if cached, ok := s.findCachedSetImage(cacheDir, setID); ok {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFile(w, r, cached)
		return
	}

	urls := s.buildSetImageURLs(set)
	for _, url := range urls {
		cached, err := s.fetchAndCacheSetImage(r.Context(), cacheDir, setID, url)
		if err != nil {
			continue
		}
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFile(w, r, cached)
		return
	}

	http.Error(w, "Image not found", http.StatusNotFound)
}

func (s *Server) buildSetImageURLs(set *models.Set) []string {
	var urls []string
	if set.ImageURL != nil && *set.ImageURL != "" {
		if s.isAllowedImageURL(*set.ImageURL) {
			urls = append(urls, *set.ImageURL)
		}
	}
	if set.SetCode != "" {
		urls = append(urls, fmt.Sprintf("https://img.bricklink.com/ItemImage/SN/0/%s.png", bricklinkSetCode(set.SetCode)))
	}
	return urls
}

func (s *Server) buildCollectionItemImageURL(image models.CollectionItemImage) string {
	if url, ok := uploads.PublicURL(s.config.Uploads, image.StorageKey); ok {
		return url
	}
	return fmt.Sprintf("/media/collection/images/%d", image.ID)
}

func (s *Server) findCachedSetImage(cacheDir string, setID int64) (string, bool) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return "", false
	}
	root, err := os.OpenRoot(cacheDir)
	if err != nil {
		return "", false
	}
	defer func() {
		if err := root.Close(); err != nil {
			log.Printf("closing image cache root: %v", err)
		}
	}()

	prefix := fmt.Sprintf("set-%d.", setID)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		info, err := entry.Info()
		if err == nil && s.imageCacheExpired(info.ModTime()) {
			_ = root.Remove(name)
			continue
		}
		return filepath.Join(cacheDir, name), true
	}

	return "", false
}

func (s *Server) imageCacheExpired(modTime time.Time) bool {
	ttl := s.config.Cache.TTL.Default
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return time.Since(modTime) > ttl
}

func (s *Server) fetchAndCacheSetImage(ctx context.Context, cacheDir string, setID int64, url string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	// #nosec G704 -- URL is validated against an allowlist.
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("closing image response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	ext := imageExtension(contentType)
	if ext == "" {
		return "", fmt.Errorf("unsupported image type")
	}

	const maxImageBytes = 8 * 1024 * 1024
	limited := io.LimitReader(resp.Body, maxImageBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", err
	}
	if int64(len(data)) > maxImageBytes {
		return "", fmt.Errorf("image too large")
	}

	filename := fmt.Sprintf("set-%d%s", setID, ext)
	root, err := os.OpenRoot(cacheDir)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := root.Close(); err != nil {
			log.Printf("closing image cache root: %v", err)
		}
	}()
	file, err := root.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}

	return filepath.Join(cacheDir, filename), nil
}

func imageExtension(contentType string) string {
	value := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	switch value {
	case "image/jpeg", "image/jpg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/webp":
		return ".webp"
	default:
		return ""
	}
}

func (s *Server) isAllowedImageURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "images.brickset.com" || host == "img.bricklink.com" {
		return true
	}
	if host == "rebrickable.com" || strings.HasSuffix(host, ".rebrickable.com") {
		return true
	}
	if s.isAllowedUploadHost(host) {
		return true
	}
	return false
}

func (s *Server) isAllowedUploadHost(host string) bool {
	publicURL := strings.TrimSpace(s.config.Uploads.S3.PublicURL)
	if publicURL == "" {
		return false
	}
	parsed, err := url.Parse(publicURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(host, parsed.Hostname())
}

func bricklinkSetCode(setCode string) string {
	trimmed := strings.TrimSpace(setCode)
	if trimmed == "" {
		return ""
	}
	if !strings.Contains(trimmed, "-") {
		return trimmed + "-1"
	}
	return trimmed
}

func (s *Server) getDashboardStats() map[string]int {
	var totalSets, totalItems, totalBrands, totalPieces int

	if err := s.db.Conn().QueryRow("SELECT COUNT(*) FROM sets").Scan(&totalSets); err != nil {
		log.Printf("dashboard sets count failed: %v", err)
	}
	if err := s.db.Conn().QueryRow("SELECT COUNT(*) FROM collection_items").Scan(&totalItems); err != nil {
		log.Printf("dashboard items count failed: %v", err)
	}
	if err := s.db.Conn().QueryRow("SELECT COUNT(*) FROM brands").Scan(&totalBrands); err != nil {
		log.Printf("dashboard brands count failed: %v", err)
	}
	if err := s.db.Conn().QueryRow("SELECT COALESCE(SUM(piece_count), 0) FROM sets").Scan(&totalPieces); err != nil {
		log.Printf("dashboard pieces count failed: %v", err)
	}

	return map[string]int{
		"TotalSets":   totalSets,
		"TotalItems":  totalItems,
		"TotalBrands": totalBrands,
		"TotalPieces": totalPieces,
	}
}

func (s *Server) getRecentCollectionItems() []models.CollectionItem {
	rows, err := s.db.Conn().Query(`
		SELECT ci.id, ci.set_id, ci.quantity, ci.condition, ci.location, ci.purchase_price,
		       ci.purchase_date, ci.missing_notes, ci.status, ci.created_at, ci.updated_at
		FROM collection_items ci
		ORDER BY ci.created_at DESC
		LIMIT 5
	`)
	if err != nil {
		return nil
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("closing recent collection rows: %v", err)
		}
	}()

	var items []models.CollectionItem
	for rows.Next() {
		var item models.CollectionItem
		err := rows.Scan(
			&item.ID, &item.SetID, &item.Quantity, &item.Condition, &item.Location,
			&item.PurchasePrice, &item.PurchaseDate, &item.MissingNotes,
			&item.Status, &item.CreatedAt, &item.UpdatedAt,
		)
		if err != nil {
			continue
		}

		if set, err := s.getSetByID(item.SetID); err == nil {
			item.Set = set
		}
		items = append(items, item)
	}
	return items
}

type dashboardInsight struct {
	Label   string
	Count   int
	Percent int
}

func (s *Server) getCollectionThemeInsights() []dashboardInsight {
	rows, err := s.db.Conn().Query(`
		SELECT COALESCE(s.theme, 'Uncategorized') AS theme,
		       COALESCE(SUM(ci.quantity), 0) AS total
		FROM collection_items ci
		JOIN sets s ON s.id = ci.set_id
		GROUP BY theme
		ORDER BY total DESC, theme
		LIMIT 6
	`)
	if err != nil {
		return nil
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("closing theme insight rows: %v", err)
		}
	}()

	var labels []string
	var counts []int
	for rows.Next() {
		var label string
		var count int
		if err := rows.Scan(&label, &count); err != nil {
			continue
		}
		labels = append(labels, label)
		counts = append(counts, count)
	}

	return buildDashboardInsights(labels, counts)
}

func (s *Server) getCollectionTagInsights() []dashboardInsight {
	rows, err := s.db.Conn().Query(`
		SELECT t.name, COALESCE(SUM(ci.quantity), 0) AS total
		FROM collection_item_tags cit
		JOIN tags t ON t.id = cit.tag_id
		JOIN collection_items ci ON ci.id = cit.collection_item_id
		GROUP BY t.name
		ORDER BY total DESC, t.name
		LIMIT 8
	`)
	if err != nil {
		return nil
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("closing tag insight rows: %v", err)
		}
	}()

	var labels []string
	var counts []int
	for rows.Next() {
		var label string
		var count int
		if err := rows.Scan(&label, &count); err != nil {
			continue
		}
		labels = append(labels, label)
		counts = append(counts, count)
	}

	return buildDashboardInsights(labels, counts)
}

func (s *Server) getSetsByBrandInsights() []dashboardInsight {
	rows, err := s.db.Conn().Query(`
		SELECT b.name, COUNT(*) AS total
		FROM sets s
		JOIN brands b ON b.id = s.brand_id
		GROUP BY b.name
		ORDER BY total DESC, b.name
		LIMIT 8
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var labels []string
	var counts []int
	for rows.Next() {
		var label string
		var count int
		if err := rows.Scan(&label, &count); err != nil {
			continue
		}
		labels = append(labels, label)
		counts = append(counts, count)
	}

	return buildDashboardInsights(labels, counts)
}

func buildDashboardInsights(labels []string, counts []int) []dashboardInsight {
	if len(labels) == 0 || len(labels) != len(counts) {
		return nil
	}

	maxCount := 0
	for _, count := range counts {
		if count > maxCount {
			maxCount = count
		}
	}
	if maxCount == 0 {
		return nil
	}

	insights := make([]dashboardInsight, 0, len(labels))
	for i, label := range labels {
		count := counts[i]
		percent := int(math.Round(float64(count) / float64(maxCount) * 100))
		if percent == 0 && count > 0 {
			percent = 1
		}
		insights = append(insights, dashboardInsight{
			Label:   label,
			Count:   count,
			Percent: percent,
		})
	}

	return insights
}

func (s *Server) getAllBrands() []models.Brand {
	rows, err := s.db.Conn().Query("SELECT id, name, kind, notes, created_at, updated_at FROM brands ORDER BY name")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var brands []models.Brand
	for rows.Next() {
		var brand models.Brand
		if err := rows.Scan(&brand.ID, &brand.Name, &brand.Kind, &brand.Notes, &brand.CreatedAt, &brand.UpdatedAt); err != nil {
			continue
		}
		brands = append(brands, brand)
	}
	return brands
}

func (s *Server) getAllSets() []models.Set {
	rows, err := s.db.Conn().Query(`
		SELECT s.id, s.brand_id, s.set_code, s.name, s.year, s.piece_count, s.minifigs,
		       s.theme, s.image_url, s.notes, s.created_at, s.updated_at,
		       b.id, b.name, b.kind, b.notes, b.created_at, b.updated_at
		FROM sets s
		JOIN brands b ON b.id = s.brand_id
		ORDER BY s.name
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var sets []models.Set
	for rows.Next() {
		var set models.Set
		var brand models.Brand
		if err := rows.Scan(
			&set.ID, &set.BrandID, &set.SetCode, &set.Name, &set.Year, &set.PieceCount,
			&set.Minifigs, &set.Theme, &set.ImageURL, &set.Notes,
			&set.CreatedAt, &set.UpdatedAt,
			&brand.ID, &brand.Name, &brand.Kind, &brand.Notes, &brand.CreatedAt, &brand.UpdatedAt,
		); err != nil {
			continue
		}
		set.Brand = &brand
		sets = append(sets, set)
	}

	s.attachTagsToSets(sets)
	return sets
}

func (s *Server) getSetsByBrandID(brandID int64) []models.Set {
	rows, err := s.db.Conn().Query(`
		SELECT s.id, s.brand_id, s.set_code, s.name, s.year, s.piece_count, s.minifigs,
		       s.theme, s.image_url, s.notes, s.created_at, s.updated_at,
		       b.id, b.name, b.kind, b.notes, b.created_at, b.updated_at
		FROM sets s
		JOIN brands b ON b.id = s.brand_id
		WHERE s.brand_id = ?
		ORDER BY s.name
	`, brandID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var sets []models.Set
	for rows.Next() {
		var set models.Set
		var brand models.Brand
		if err := rows.Scan(
			&set.ID, &set.BrandID, &set.SetCode, &set.Name, &set.Year, &set.PieceCount,
			&set.Minifigs, &set.Theme, &set.ImageURL, &set.Notes,
			&set.CreatedAt, &set.UpdatedAt,
			&brand.ID, &brand.Name, &brand.Kind, &brand.Notes, &brand.CreatedAt, &brand.UpdatedAt,
		); err != nil {
			continue
		}
		set.Brand = &brand
		sets = append(sets, set)
	}

	s.attachTagsToSets(sets)
	return sets
}

func (s *Server) getFilteredSets(search, theme string, tags []string, brandID int64) []models.Set {
	var args []interface{}
	clauses := make([]string, 0, 4)
	joins := ""

	if brandID != 0 {
		clauses = append(clauses, "s.brand_id = ?")
		args = append(args, brandID)
	}
	if search != "" {
		value := "%" + strings.ToLower(search) + "%"
		clauses = append(clauses, "(LOWER(s.name) LIKE ? OR LOWER(s.set_code) LIKE ?)")
		args = append(args, value, value)
	}
	if theme != "" {
		value := "%" + strings.ToLower(theme) + "%"
		clauses = append(clauses, "(s.theme IS NOT NULL AND LOWER(s.theme) LIKE ?)")
		args = append(args, value)
	}
	if len(tags) > 0 {
		joins = "JOIN set_tags st ON st.set_id = s.id JOIN tags t ON t.id = st.tag_id"
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		clauses = append(clauses, fmt.Sprintf("t.name IN (%s)", placeholders))
		for _, tag := range tags {
			args = append(args, normalizeTagName(tag))
		}
	}

	query := `
		SELECT s.id, s.brand_id, s.set_code, s.name, s.year, s.piece_count, s.minifigs,
		       s.theme, s.image_url, s.notes, s.created_at, s.updated_at,
		       b.id, b.name, b.kind, b.notes, b.created_at, b.updated_at
		FROM sets s
		JOIN brands b ON b.id = s.brand_id
	`
	if joins != "" {
		query += "\n" + joins
	}
	if len(clauses) > 0 {
		query += "\nWHERE " + strings.Join(clauses, " AND ")
	}
	if len(tags) > 0 {
		query += "\nGROUP BY s.id, b.id HAVING COUNT(DISTINCT t.name) = ?"
		args = append(args, len(tags))
	}
	query += "\nORDER BY s.name"

	// #nosec G701 -- query uses parameterized args and controlled joins.
	rows, err := s.db.Conn().Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var sets []models.Set
	for rows.Next() {
		var set models.Set
		var brand models.Brand
		if err := rows.Scan(
			&set.ID, &set.BrandID, &set.SetCode, &set.Name, &set.Year, &set.PieceCount,
			&set.Minifigs, &set.Theme, &set.ImageURL, &set.Notes,
			&set.CreatedAt, &set.UpdatedAt,
			&brand.ID, &brand.Name, &brand.Kind, &brand.Notes, &brand.CreatedAt, &brand.UpdatedAt,
		); err != nil {
			continue
		}
		set.Brand = &brand
		sets = append(sets, set)
	}

	s.attachTagsToSets(sets)
	return sets
}

func (s *Server) getFilteredCollectionItems(status, condition string, tags []string) []models.CollectionItem {
	var args []interface{}
	clauses := make([]string, 0, 3)
	joins := ""

	statusValue := strings.ToLower(strings.TrimSpace(status))
	if statusValue != "" {
		clauses = append(clauses, "ci.status = ?")
		args = append(args, statusValue)
	}
	conditionValue := strings.ToLower(strings.TrimSpace(condition))
	if conditionValue != "" {
		clauses = append(clauses, "ci.condition = ?")
		args = append(args, conditionValue)
	}
	if len(tags) > 0 {
		joins = "JOIN collection_item_tags cit ON cit.collection_item_id = ci.id JOIN tags t ON t.id = cit.tag_id"
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = strings.TrimRight(placeholders, ",")
		clauses = append(clauses, fmt.Sprintf("t.name IN (%s)", placeholders))
		for _, tag := range tags {
			args = append(args, normalizeTagName(tag))
		}
	}

	query := `
		SELECT ci.id, ci.set_id, ci.quantity, ci.condition, ci.location, ci.purchase_price,
		       ci.purchase_date, ci.missing_notes, ci.status, ci.created_at, ci.updated_at,
		       s.id, s.set_code, s.name
		FROM collection_items ci
		JOIN sets s ON s.id = ci.set_id
	`
	if joins != "" {
		query += "\n" + joins
	}
	if len(clauses) > 0 {
		query += "\nWHERE " + strings.Join(clauses, " AND ")
	}
	if len(tags) > 0 {
		query += "\nGROUP BY ci.id, s.id HAVING COUNT(DISTINCT t.name) = ?"
		args = append(args, len(tags))
	}
	query += "\nORDER BY ci.created_at DESC"

	rows, err := s.db.Conn().Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var items []models.CollectionItem
	for rows.Next() {
		var item models.CollectionItem
		var set models.Set
		if err := rows.Scan(
			&item.ID, &item.SetID, &item.Quantity, &item.Condition, &item.Location,
			&item.PurchasePrice, &item.PurchaseDate, &item.MissingNotes,
			&item.Status, &item.CreatedAt, &item.UpdatedAt,
			&set.ID, &set.SetCode, &set.Name,
		); err != nil {
			continue
		}
		item.Set = &set
		items = append(items, item)
	}

	s.attachTagsToCollectionItems(items)
	return items
}

func currentUser(r *http.Request) (*auth.Claims, bool) {
	claims, ok := r.Context().Value(userContextKey).(*auth.Claims)
	if !ok || claims == nil {
		return nil, false
	}
	return claims, true
}

func normalizeRole(role string) models.UserRole {
	parsed := models.UserRole(strings.TrimSpace(role))
	if parsed.Valid() {
		return parsed
	}
	return models.RoleViewer
}

func roleAllowed(role models.UserRole, allowed ...models.UserRole) bool {
	for _, candidate := range allowed {
		if role == candidate {
			return true
		}
	}
	return false
}

func rolePolicyForRequest(r *http.Request) ([]models.UserRole, bool) {
	routePattern := r.URL.Path
	if routeCtx := chi.RouteContext(r.Context()); routeCtx != nil {
		if pattern := routeCtx.RoutePattern(); pattern != "" {
			routePattern = pattern
		}
	}

	key := fmt.Sprintf("%s %s", r.Method, routePattern)
	roles, ok := rolePolicies[key]
	return roles, ok
}

func respondUnauthorized(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		if err := json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"}); err != nil {
			log.Printf("encode unauthorized response: %v", err)
		}
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func respondForbidden(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"}); err != nil {
			log.Printf("encode forbidden response: %v", err)
		}
		return
	}
	http.Error(w, "Forbidden", http.StatusForbidden)
}

func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("encode json response: %v", err)
	}
}

var rolePolicies = map[string][]models.UserRole{
	"GET /profile":                                       {models.RoleAdmin, models.RoleEditor, models.RoleViewer},
	"POST /profile/password":                             {models.RoleAdmin, models.RoleEditor, models.RoleViewer},
	"POST /profile/disable":                              {models.RoleAdmin, models.RoleEditor, models.RoleViewer},
	"POST /profile/api-tokens":                           {models.RoleAdmin, models.RoleEditor, models.RoleViewer},
	"POST /profile/api-tokens/{id}/revoke":               {models.RoleAdmin, models.RoleEditor, models.RoleViewer},
	"POST /profile/api-tokens/clear-warning":             {models.RoleAdmin, models.RoleEditor, models.RoleViewer},
	"GET /admin/users":                                   {models.RoleAdmin},
	"GET /admin/users/new":                               {models.RoleAdmin},
	"GET /admin/users/{id}/edit":                         {models.RoleAdmin},
	"POST /admin/users":                                  {models.RoleAdmin},
	"POST /admin/users/{id}/update":                      {models.RoleAdmin},
	"POST /admin/users/{id}/delete":                      {models.RoleAdmin},
	"POST /admin/users/{id}/disable":                     {models.RoleAdmin},
	"POST /admin/users/{id}/enable":                      {models.RoleAdmin},
	"POST /admin/users/{id}/api-tokens/{tokenID}/revoke": {models.RoleAdmin},

	"GET /brands/new":          {models.RoleAdmin, models.RoleEditor},
	"GET /brands/{id}/edit":    {models.RoleAdmin, models.RoleEditor},
	"GET /brands/{id}":         {models.RoleAdmin, models.RoleEditor, models.RoleViewer},
	"POST /brands":             {models.RoleAdmin, models.RoleEditor},
	"POST /brands/{id}/update": {models.RoleAdmin, models.RoleEditor},
	"POST /brands/{id}/delete": {models.RoleAdmin},

	"GET /sets/new":          {models.RoleAdmin, models.RoleEditor},
	"GET /sets/{id}/edit":    {models.RoleAdmin, models.RoleEditor},
	"POST /sets":             {models.RoleAdmin, models.RoleEditor},
	"POST /sets/{id}/update": {models.RoleAdmin, models.RoleEditor},
	"POST /sets/{id}/delete": {models.RoleAdmin},

	"GET /collection/new":                           {models.RoleAdmin, models.RoleEditor},
	"GET /collection/{id}/edit":                     {models.RoleAdmin, models.RoleEditor},
	"POST /collection":                              {models.RoleAdmin, models.RoleEditor},
	"POST /collection/{id}/update":                  {models.RoleAdmin, models.RoleEditor},
	"POST /collection/{id}/delete":                  {models.RoleAdmin},
	"POST /collection/{id}/images":                  {models.RoleAdmin, models.RoleEditor},
	"POST /collection/{id}/images/{imageID}/delete": {models.RoleAdmin, models.RoleEditor},
	"GET /import":                                   {models.RoleAdmin, models.RoleEditor},
	"POST /import/upload":                           {models.RoleAdmin, models.RoleEditor},
	"POST /import/confirm":                          {models.RoleAdmin, models.RoleEditor},
	"GET /export":                                   {models.RoleAdmin, models.RoleEditor, models.RoleViewer},
	"GET /export/rebrickable":                       {models.RoleAdmin, models.RoleEditor, models.RoleViewer},
	"GET /export/brickset":                          {models.RoleAdmin, models.RoleEditor, models.RoleViewer},
	"GET /export/blocks":                            {models.RoleAdmin, models.RoleEditor, models.RoleViewer},

	"GET /api/users":               {models.RoleAdmin},
	"POST /api/users":              {models.RoleAdmin},
	"PUT /api/users/{id}":          {models.RoleAdmin},
	"POST /api/users/{id}/disable": {models.RoleAdmin},
	"POST /api/users/{id}/enable":  {models.RoleAdmin},
	"DELETE /api/users/{id}":       {models.RoleAdmin},

	"POST /api/brands":                       {models.RoleAdmin, models.RoleEditor},
	"PUT /api/brands/{id}":                   {models.RoleAdmin, models.RoleEditor},
	"DELETE /api/brands/{id}":                {models.RoleAdmin},
	"POST /api/sets":                         {models.RoleAdmin, models.RoleEditor},
	"PUT /api/sets/{id}":                     {models.RoleAdmin, models.RoleEditor},
	"DELETE /api/sets/{id}":                  {models.RoleAdmin},
	"POST /api/collection":                   {models.RoleAdmin, models.RoleEditor},
	"PUT /api/collection/{id}":               {models.RoleAdmin, models.RoleEditor},
	"DELETE /api/collection/{id}":            {models.RoleAdmin},
	"POST /api/valuations/sets/{id}/refresh": {models.RoleAdmin, models.RoleEditor},
	"GET /api/tags":                          {models.RoleAdmin, models.RoleEditor, models.RoleViewer},
	"GET /api/providers/sets/{setNum}":       {models.RoleAdmin, models.RoleEditor},
	"GET /api/auth/ping":                     {models.RoleAdmin, models.RoleEditor, models.RoleViewer},
}

var apiScopePolicies = map[string]string{
	"POST /api/auth/logout": apiTokenScopeWrite,

	"GET /api/users":               apiTokenScopeAdmin,
	"POST /api/users":              apiTokenScopeAdmin,
	"PUT /api/users/{id}":          apiTokenScopeAdmin,
	"POST /api/users/{id}/disable": apiTokenScopeAdmin,
	"POST /api/users/{id}/enable":  apiTokenScopeAdmin,
	"DELETE /api/users/{id}":       apiTokenScopeAdmin,

	"GET /api/brands":         apiTokenScopeRead,
	"GET /api/brands/{id}":    apiTokenScopeRead,
	"POST /api/brands":        apiTokenScopeWrite,
	"PUT /api/brands/{id}":    apiTokenScopeWrite,
	"DELETE /api/brands/{id}": apiTokenScopeWrite,

	"GET /api/sets":         apiTokenScopeRead,
	"GET /api/sets/{id}":    apiTokenScopeRead,
	"POST /api/sets":        apiTokenScopeWrite,
	"PUT /api/sets/{id}":    apiTokenScopeWrite,
	"DELETE /api/sets/{id}": apiTokenScopeWrite,

	"GET /api/collection":         apiTokenScopeRead,
	"POST /api/collection":        apiTokenScopeWrite,
	"PUT /api/collection/{id}":    apiTokenScopeWrite,
	"DELETE /api/collection/{id}": apiTokenScopeWrite,

	"GET /api/tags": apiTokenScopeRead,

	"GET /api/providers/sets/{setNum}": apiTokenScopeRead,

	"POST /api/valuations/sets/{id}/refresh": apiTokenScopeWrite,
	"GET /api/auth/ping":                     apiTokenScopeRead,
}

func (s *Server) ensureSingleUserAdmin(userID int64, role string) (string, error) {
	var count int
	if err := s.db.Conn().QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return role, err
	}
	if count != 1 {
		return role, nil
	}
	if role == string(models.RoleAdmin) {
		return role, nil
	}

	if _, err := s.db.Conn().Exec("UPDATE users SET role = ? WHERE id = ?", models.RoleAdmin, userID); err != nil {
		return role, err
	}
	return string(models.RoleAdmin), nil
}

func parseSetForm(r *http.Request) (*models.Set, error) {
	name := strings.TrimSpace(r.FormValue("name"))
	setCode := strings.TrimSpace(r.FormValue("set_code"))
	brandIDValue := strings.TrimSpace(r.FormValue("brand_id"))
	if name == "" || setCode == "" || brandIDValue == "" {
		return &models.Set{Name: name, SetCode: setCode}, fmt.Errorf("name, set code, and brand are required")
	}

	brandID, err := strconv.ParseInt(brandIDValue, 10, 64)
	if err != nil {
		return &models.Set{Name: name, SetCode: setCode}, fmt.Errorf("invalid brand selection")
	}

	year, err := parseOptionalInt(r.FormValue("year"))
	if err != nil {
		return &models.Set{Name: name, SetCode: setCode, BrandID: brandID}, fmt.Errorf("invalid year")
	}
	pieceCount, err := parseOptionalInt(r.FormValue("piece_count"))
	if err != nil {
		return &models.Set{Name: name, SetCode: setCode, BrandID: brandID}, fmt.Errorf("invalid piece count")
	}
	minifigs, err := parseOptionalInt(r.FormValue("minifigs"))
	if err != nil {
		return &models.Set{Name: name, SetCode: setCode, BrandID: brandID}, fmt.Errorf("invalid minifigs count")
	}

	set := &models.Set{
		Name:       name,
		SetCode:    setCode,
		BrandID:    brandID,
		Year:       year,
		PieceCount: pieceCount,
		Minifigs:   minifigs,
		Theme:      parseOptionalString(r.FormValue("theme")),
		ImageURL:   parseOptionalString(r.FormValue("image_url")),
		Notes:      parseOptionalString(r.FormValue("notes")),
	}

	return set, nil
}

func parseCollectionForm(r *http.Request) (*models.CollectionItem, error) {
	setIDValue := strings.TrimSpace(r.FormValue("set_id"))
	quantityValue := strings.TrimSpace(r.FormValue("quantity"))
	conditionValue := strings.TrimSpace(r.FormValue("condition"))
	statusValue := strings.TrimSpace(r.FormValue("status"))

	if setIDValue == "" || quantityValue == "" || conditionValue == "" || statusValue == "" {
		return &models.CollectionItem{}, fmt.Errorf("set, quantity, condition, and status are required")
	}

	setID, err := strconv.ParseInt(setIDValue, 10, 64)
	if err != nil {
		return &models.CollectionItem{}, fmt.Errorf("invalid set selection")
	}
	quantity, err := strconv.Atoi(quantityValue)
	if err != nil || quantity < 1 {
		return &models.CollectionItem{SetID: setID}, fmt.Errorf("quantity must be at least 1")
	}

	condition := models.ItemCondition(conditionValue)
	if !condition.Valid() {
		return &models.CollectionItem{SetID: setID, Quantity: quantity}, fmt.Errorf("invalid condition")
	}

	status := models.ItemStatus(statusValue)
	if !status.Valid() {
		return &models.CollectionItem{SetID: setID, Quantity: quantity, Condition: condition}, fmt.Errorf("invalid status")
	}

	purchasePrice, err := parseOptionalFloat(r.FormValue("purchase_price"))
	if err != nil {
		return &models.CollectionItem{SetID: setID, Quantity: quantity, Condition: condition, Status: status}, fmt.Errorf("invalid purchase price")
	}

	purchaseDate, err := parseOptionalDate(r.FormValue("purchase_date"))
	if err != nil {
		return &models.CollectionItem{SetID: setID, Quantity: quantity, Condition: condition, Status: status}, fmt.Errorf("invalid purchase date")
	}

	item := &models.CollectionItem{
		SetID:         setID,
		Quantity:      quantity,
		Condition:     condition,
		Status:        status,
		Location:      parseOptionalString(r.FormValue("location")),
		PurchasePrice: purchasePrice,
		PurchaseDate:  purchaseDate,
		MissingNotes:  parseOptionalString(r.FormValue("missing_notes")),
	}

	return item, nil
}

func parseTagInput(input string) []string {
	if input == "" {
		return nil
	}

	parts := strings.FieldsFunc(input, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})

	seen := make(map[string]bool)
	var tags []string
	for _, part := range parts {
		normalized := normalizeTagName(part)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		tags = append(tags, normalized)
	}

	return tags
}

func normalizeTagName(name string) string {
	return strings.TrimSpace(strings.ToLower(name))
}

func (s *Server) replaceSetTags(tx *sql.Tx, setID int64, tags []string) error {
	if _, err := tx.Exec("DELETE FROM set_tags WHERE set_id = ?", setID); err != nil {
		return err
	}
	return s.insertTagLinks(tx, "set_tags", "set_id", setID, tags)
}

func (s *Server) replaceCollectionItemTags(tx *sql.Tx, itemID int64, tags []string) error {
	if _, err := tx.Exec("DELETE FROM collection_item_tags WHERE collection_item_id = ?", itemID); err != nil {
		return err
	}
	return s.insertTagLinks(tx, "collection_item_tags", "collection_item_id", itemID, tags)
}

func (s *Server) insertTagLinks(tx *sql.Tx, table string, idColumn string, parentID int64, tags []string) error {
	if len(tags) == 0 {
		return nil
	}

	tagIDs, err := s.ensureTagIDs(tx, tags)
	if err != nil {
		return err
	}

	var statement string
	switch table {
	case "set_tags":
		if idColumn != "set_id" {
			return fmt.Errorf("invalid tag column")
		}
		statement = "INSERT OR IGNORE INTO set_tags (set_id, tag_id) VALUES (?, ?)"
	case "collection_item_tags":
		if idColumn != "collection_item_id" {
			return fmt.Errorf("invalid tag column")
		}
		statement = "INSERT OR IGNORE INTO collection_item_tags (collection_item_id, tag_id) VALUES (?, ?)"
	default:
		return fmt.Errorf("invalid tag table")
	}
	for _, name := range tags {
		tagID, ok := tagIDs[name]
		if !ok {
			continue
		}
		if _, err := tx.Exec(statement, parentID, tagID); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) ensureTagIDs(tx *sql.Tx, tags []string) (map[string]int64, error) {
	if len(tags) == 0 {
		return map[string]int64{}, nil
	}

	for _, name := range tags {
		if _, err := tx.Exec("INSERT OR IGNORE INTO tags (name) VALUES (?)", name); err != nil {
			return nil, err
		}
	}

	placeholders := buildPlaceholders(len(tags))
	// #nosec G202 -- placeholders are generated from count; args are parameterized.
	query := "SELECT id, name FROM tags WHERE name IN (" + placeholders + ")"
	args := make([]interface{}, 0, len(tags))
	for _, name := range tags {
		args = append(args, name)
	}

	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int64, len(tags))
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		result[name] = id
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func (s *Server) attachTagsToSets(sets []models.Set) {
	if len(sets) == 0 {
		return
	}

	ids := make([]interface{}, 0, len(sets))
	index := make(map[int64]int, len(sets))
	for i := range sets {
		ids = append(ids, sets[i].ID)
		index[sets[i].ID] = i
	}

	placeholders := buildPlaceholders(len(ids))
	query := fmt.Sprintf(`
		SELECT st.set_id, t.name
		FROM set_tags st
		JOIN tags t ON t.id = st.tag_id
		WHERE st.set_id IN (%s)
		ORDER BY t.name
	`, placeholders)
	rows, err := s.db.Conn().Query(query, ids...)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var setID int64
		var name string
		if err := rows.Scan(&setID, &name); err != nil {
			continue
		}
		if idx, ok := index[setID]; ok {
			sets[idx].Tags = append(sets[idx].Tags, name)
		}
	}
}

func (s *Server) attachTagsToCollectionItems(items []models.CollectionItem) {
	if len(items) == 0 {
		return
	}

	ids := make([]interface{}, 0, len(items))
	index := make(map[int64]int, len(items))
	for i := range items {
		ids = append(ids, items[i].ID)
		index[items[i].ID] = i
	}

	placeholders := buildPlaceholders(len(ids))
	query := fmt.Sprintf(`
		SELECT cit.collection_item_id, t.name
		FROM collection_item_tags cit
		JOIN tags t ON t.id = cit.tag_id
		WHERE cit.collection_item_id IN (%s)
		ORDER BY t.name
	`, placeholders)
	rows, err := s.db.Conn().Query(query, ids...)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var itemID int64
		var name string
		if err := rows.Scan(&itemID, &name); err != nil {
			continue
		}
		if idx, ok := index[itemID]; ok {
			items[idx].Tags = append(items[idx].Tags, name)
		}
	}
}

func (s *Server) attachImagesToCollectionItems(items []models.CollectionItem) {
	if len(items) == 0 {
		return
	}

	ids := make([]interface{}, 0, len(items))
	index := make(map[int64]int, len(items))
	for i := range items {
		ids = append(ids, items[i].ID)
		index[items[i].ID] = i
	}

	placeholders := buildPlaceholders(len(ids))
	query := fmt.Sprintf(`
		SELECT id, collection_item_id, storage_key, content_type, created_at
		FROM collection_item_images
		WHERE collection_item_id IN (%s)
		ORDER BY created_at DESC
	`, placeholders)
	rows, err := s.db.Conn().Query(query, ids...)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var image models.CollectionItemImage
		if err := rows.Scan(
			&image.ID, &image.CollectionItemID, &image.StorageKey, &image.ContentType, &image.CreatedAt,
		); err != nil {
			continue
		}
		url := s.buildCollectionItemImageURL(image)
		image.PublicURL = &url
		if idx, ok := index[image.CollectionItemID]; ok {
			items[idx].Images = append(items[idx].Images, image)
		}
	}
}

func (s *Server) getTagsForSetID(setID int64) []string {
	rows, err := s.db.Conn().Query(
		`SELECT t.name
		 FROM set_tags st
		 JOIN tags t ON t.id = st.tag_id
		 WHERE st.set_id = ?
		 ORDER BY t.name`,
		setID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var tags []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		tags = append(tags, name)
	}
	return tags
}

func (s *Server) getTagsForCollectionItemID(itemID int64) []string {
	rows, err := s.db.Conn().Query(
		`SELECT t.name
		 FROM collection_item_tags cit
		 JOIN tags t ON t.id = cit.tag_id
		 WHERE cit.collection_item_id = ?
		 ORDER BY t.name`,
		itemID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var tags []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		tags = append(tags, name)
	}
	return tags
}

func buildPlaceholders(count int) string {
	if count <= 0 {
		return ""
	}
	return strings.TrimRight(strings.Repeat("?,", count), ",")
}

func parseOptionalString(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func parseOptionalInt(value string) (*int, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	parsed, err := strconv.Atoi(trimmed)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func parseOptionalFloat(value string) (*float64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func parseOptionalDate(value string) (*time.Time, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	parsed, err := time.Parse("2006-01-02", trimmed)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func (s *Server) hashPassword(password string) (string, error) {
	cost := s.config.Auth.BcryptCost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (s *Server) listUsers() []models.User {
	rows, err := s.db.Conn().Query("SELECT id, username, role, disabled_at, created_at FROM users ORDER BY username")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		if err := rows.Scan(&user.ID, &user.Username, &user.Role, &user.DisabledAt, &user.CreatedAt); err != nil {
			continue
		}
		users = append(users, user)
	}

	return users
}

func (s *Server) listUserAPITokens(userID int64) []apiTokenView {
	rows, err := s.db.Conn().Query(`
		SELECT id, name, scope, created_at, last_used_at, expires_at, revoked_at
		FROM api_tokens
		WHERE user_id = ?
		ORDER BY revoked_at IS NULL DESC, created_at DESC
	`, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var tokens []apiTokenView
	for rows.Next() {
		var token apiTokenView
		if err := rows.Scan(&token.ID, &token.Name, &token.Scope, &token.CreatedAt, &token.LastUsedAt, &token.ExpiresAt, &token.RevokedAt); err != nil {
			return nil
		}
		if token.RevokedAt != nil && s.apiTokensRevokedAt != nil && !token.RevokedAt.Before(*s.apiTokensRevokedAt) {
			token.RevokedBySecret = true
		}
		tokens = append(tokens, token)
	}
	return tokens
}

func (s *Server) lookupAPIToken(hash string) (int64, int64, string, *time.Time, *time.Time, error) {
	var tokenID int64
	var userID int64
	var scope string
	var expiresAt *time.Time
	var revokedAt *time.Time
	row := s.db.Conn().QueryRow(
		"SELECT id, user_id, scope, expires_at, revoked_at FROM api_tokens WHERE token_hash = ?",
		hash,
	)
	if err := row.Scan(&tokenID, &userID, &scope, &expiresAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, "", nil, nil, errAPITokenNotFound
		}
		return 0, 0, "", nil, nil, err
	}
	return tokenID, userID, scope, expiresAt, revokedAt, nil
}

func (s *Server) createAPIToken(userID int64, name, scope string) (string, error) {
	trimmedScope := strings.TrimSpace(scope)
	if trimmedScope != apiTokenScopeRead && trimmedScope != apiTokenScopeWrite && trimmedScope != apiTokenScopeAdmin {
		return "", fmt.Errorf("invalid scope")
	}
	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		trimmedName = ""
	}

	token, err := generateAPIToken()
	if err != nil {
		return "", err
	}
	hash := s.hashAPIToken(token)

	var nameValue interface{}
	if trimmedName == "" {
		nameValue = nil
	} else {
		nameValue = trimmedName
	}

	expiresAt := time.Now().Add(apiTokenTTL)
	_, err = s.db.Conn().Exec(
		"INSERT INTO api_tokens (user_id, name, token_hash, scope, expires_at) VALUES (?, ?, ?, ?, ?)",
		userID,
		nameValue,
		hash,
		trimmedScope,
		expiresAt,
	)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (s *Server) getUserByID(id int64) (*models.User, error) {
	var user models.User
	err := s.db.Conn().QueryRow("SELECT id, username, role, disabled_at, created_at FROM users WHERE id = ?", id).Scan(
		&user.ID,
		&user.Username,
		&user.Role,
		&user.DisabledAt,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Server) redirectAdminUsersError(w http.ResponseWriter, r *http.Request, message string) {
	url := fmt.Sprintf("/admin/users?error=%s", url.QueryEscape(message))
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (s *Server) redirectAdminUsersMessage(w http.ResponseWriter, r *http.Request, message string) {
	url := fmt.Sprintf("/admin/users?message=%s", url.QueryEscape(message))
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func addFlashFromQuery(r *http.Request, data map[string]interface{}) {
	if message := strings.TrimSpace(r.URL.Query().Get("message")); message != "" {
		data["Message"] = message
	}
	if errMsg := strings.TrimSpace(r.URL.Query().Get("error")); errMsg != "" {
		data["Error"] = errMsg
	}
}

func redirectWithMessage(w http.ResponseWriter, r *http.Request, baseURL, message string) {
	url := fmt.Sprintf("%s?message=%s", baseURL, url.QueryEscape(message))
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func redirectWithError(w http.ResponseWriter, r *http.Request, baseURL, message string) {
	url := fmt.Sprintf("%s?error=%s", baseURL, url.QueryEscape(message))
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (s *Server) disableUser(id int64) error {
	_, err := s.db.Conn().Exec("UPDATE users SET disabled_at = CURRENT_TIMESTAMP WHERE id = ?", id)
	return err
}

func (s *Server) ensureCanRemoveUser(id int64) error {
	user, err := s.getUserByID(id)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if normalizeRole(user.Role.String()) != models.RoleAdmin {
		return nil
	}

	var adminCount int
	if err := s.db.Conn().QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&adminCount); err != nil {
		return err
	}
	if adminCount <= 1 {
		return fmt.Errorf("cannot remove the last admin")
	}
	return nil
}

func (s *Server) ensureCanChangeRole(id int64, currentRole models.UserRole, nextRole models.UserRole) error {
	if currentRole == nextRole {
		return nil
	}
	if currentRole != models.RoleAdmin {
		return nil
	}

	var adminCount int
	if err := s.db.Conn().QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&adminCount); err != nil {
		return err
	}
	if adminCount <= 1 {
		return fmt.Errorf("cannot demote the last admin")
	}
	return nil
}

func (s *Server) getSetByID(id int64) (*models.Set, error) {
	var set models.Set
	err := s.db.Conn().QueryRow(`
		SELECT id, brand_id, set_code, name, year, piece_count, minifigs,
		       theme, image_url, notes, created_at, updated_at
		FROM sets WHERE id = ?
	`, id).Scan(
		&set.ID, &set.BrandID, &set.SetCode, &set.Name, &set.Year, &set.PieceCount,
		&set.Minifigs, &set.Theme, &set.ImageURL, &set.Notes,
		&set.CreatedAt, &set.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	if brand, err := s.getBrandByID(set.BrandID); err == nil {
		set.Brand = brand
	}
	set.Tags = s.getTagsForSetID(set.ID)

	return &set, nil
}

func (s *Server) getBrandByID(id int64) (*models.Brand, error) {
	var brand models.Brand
	err := s.db.Conn().QueryRow(
		"SELECT id, name, kind, notes, created_at, updated_at FROM brands WHERE id = ?",
		id,
	).Scan(&brand.ID, &brand.Name, &brand.Kind, &brand.Notes, &brand.CreatedAt, &brand.UpdatedAt)

	return &brand, err
}

func (s *Server) getCollectionItemByID(id int64) (*models.CollectionItem, error) {
	var item models.CollectionItem
	err := s.db.Conn().QueryRow(`
		SELECT id, set_id, quantity, condition, location, purchase_price,
		       purchase_date, missing_notes, status, created_at, updated_at
		FROM collection_items WHERE id = ?
	`, id).Scan(
		&item.ID, &item.SetID, &item.Quantity, &item.Condition, &item.Location,
		&item.PurchasePrice, &item.PurchaseDate, &item.MissingNotes,
		&item.Status, &item.CreatedAt, &item.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	if set, err := s.getSetByID(item.SetID); err == nil {
		item.Set = set
	}
	item.Tags = s.getTagsForCollectionItemID(item.ID)
	item.Images = s.getCollectionItemImages(item.ID)

	return &item, nil
}

func (s *Server) getCollectionItemImages(itemID int64) []models.CollectionItemImage {
	rows, err := s.db.Conn().Query(
		`SELECT id, collection_item_id, storage_key, content_type, created_at
		 FROM collection_item_images
		 WHERE collection_item_id = ?
		 ORDER BY created_at DESC`,
		itemID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var images []models.CollectionItemImage
	for rows.Next() {
		var image models.CollectionItemImage
		if err := rows.Scan(
			&image.ID, &image.CollectionItemID, &image.StorageKey, &image.ContentType, &image.CreatedAt,
		); err != nil {
			continue
		}
		url := s.buildCollectionItemImageURL(image)
		image.PublicURL = &url
		images = append(images, image)
	}
	return images
}

func (s *Server) getCollectionItemImageByID(id int64) (*models.CollectionItemImage, error) {
	var image models.CollectionItemImage
	err := s.db.Conn().QueryRow(
		`SELECT id, collection_item_id, storage_key, content_type, created_at
		 FROM collection_item_images
		 WHERE id = ?`,
		id,
	).Scan(&image.ID, &image.CollectionItemID, &image.StorageKey, &image.ContentType, &image.CreatedAt)
	if err != nil {
		return nil, err
	}
	url := s.buildCollectionItemImageURL(image)
	image.PublicURL = &url
	return &image, nil
}

func (s *Server) getValuationsForSet(setID int64) ([]models.Valuation, error) {
	rows, err := s.db.Conn().Query(`
		SELECT id, set_id, provider, currency, condition, metric, value,
		       sample_size, confidence, as_of_date, raw_json, created_at
		FROM valuations 
		WHERE set_id = ?
		ORDER BY created_at DESC
	`, setID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var valuations []models.Valuation
	for rows.Next() {
		var valuation models.Valuation
		err := rows.Scan(
			&valuation.ID, &valuation.SetID, &valuation.Provider, &valuation.Currency,
			&valuation.Condition, &valuation.Metric, &valuation.Value,
			&valuation.SampleSize, &valuation.Confidence, &valuation.AsOfDate,
			&valuation.RawJSON, &valuation.CreatedAt,
		)
		if err != nil {
			continue
		}
		valuations = append(valuations, valuation)
	}
	return valuations, nil
}

func (s *Server) getCollectionItemsForSet(setID int64) ([]models.CollectionItem, error) {
	rows, err := s.db.Conn().Query(`
		SELECT id, set_id, quantity, condition, location, purchase_price,
		       purchase_date, missing_notes, status, created_at, updated_at
		FROM collection_items 
		WHERE set_id = ?
		ORDER BY created_at DESC
	`, setID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []models.CollectionItem
	for rows.Next() {
		var item models.CollectionItem
		err := rows.Scan(
			&item.ID, &item.SetID, &item.Quantity, &item.Condition, &item.Location,
			&item.PurchasePrice, &item.PurchaseDate, &item.MissingNotes,
			&item.Status, &item.CreatedAt, &item.UpdatedAt,
		)
		if err != nil {
			continue
		}
		items = append(items, item)
	}

	s.attachTagsToCollectionItems(items)
	s.attachImagesToCollectionItems(items)
	return items, nil
}

func (s *Server) buildCollectionImageGallery(items []models.CollectionItem) []collectionImageView {
	if len(items) == 0 {
		return nil
	}

	var images []collectionImageView
	for _, item := range items {
		for _, image := range item.Images {
			images = append(images, collectionImageView{
				Image:     image,
				ItemID:    item.ID,
				Condition: item.Condition,
				Status:    item.Status,
			})
		}
	}
	return images
}

func (s *Server) handleListBrands(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.getAllBrands()); err != nil {
		log.Printf("encode brands response: %v", err)
	}
}

func (s *Server) handleCreateBrand(w http.ResponseWriter, r *http.Request) {
	var brand models.Brand
	if err := json.NewDecoder(r.Body).Decode(&brand); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if !brand.Kind.Valid() {
		http.Error(w, "Invalid brand kind", http.StatusBadRequest)
		return
	}

	result, err := s.db.Conn().Exec(
		"INSERT INTO brands (name, kind, notes) VALUES (?, ?, ?)",
		brand.Name, brand.Kind, brand.Notes,
	)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	brand.ID = id
	brand.CreatedAt = time.Now()
	brand.UpdatedAt = time.Now()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(brand); err != nil {
		log.Printf("encode brand response: %v", err)
	}
}

func (s *Server) handleGetBrand(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	brand, err := s.getBrandByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Brand not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(brand); err != nil {
		log.Printf("encode brand response: %v", err)
	}
}

func (s *Server) handleUpdateBrand(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var brand models.Brand
	if err := json.NewDecoder(r.Body).Decode(&brand); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if !brand.Kind.Valid() {
		http.Error(w, "Invalid brand kind", http.StatusBadRequest)
		return
	}

	_, err = s.db.Conn().Exec(
		"UPDATE brands SET name = ?, kind = ?, notes = ? WHERE id = ?",
		brand.Name, brand.Kind, brand.Notes, id,
	)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	brand.ID = id
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(brand); err != nil {
		log.Printf("encode brand response: %v", err)
	}
}

func (s *Server) handleDeleteBrand(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	_, err = s.db.Conn().Exec("DELETE FROM brands WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListSets(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	theme := strings.TrimSpace(r.URL.Query().Get("theme"))
	tagsInput := strings.TrimSpace(r.URL.Query().Get("tags"))
	filterTags := parseTagInput(tagsInput)
	brandIDStr := strings.TrimSpace(r.URL.Query().Get("brand"))
	var brandID int64
	if brandIDStr != "" {
		parsedID, err := strconv.ParseInt(brandIDStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid brand", http.StatusBadRequest)
			return
		}
		brandID = parsedID
	}

	sets := s.getFilteredSets(search, theme, filterTags, brandID)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sets); err != nil {
		log.Printf("encode sets response: %v", err)
	}
}

func (s *Server) handleCreateSet(w http.ResponseWriter, r *http.Request) {
	var set models.Set
	if err := json.NewDecoder(r.Body).Decode(&set); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	result, err := s.db.Conn().Exec(
		"INSERT INTO sets (brand_id, set_code, name, year, piece_count, minifigs, theme, image_url, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		set.BrandID, set.SetCode, set.Name, set.Year, set.PieceCount, set.Minifigs,
		set.Theme, set.ImageURL, set.Notes,
	)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	set.ID = id
	set.CreatedAt = time.Now()
	set.UpdatedAt = time.Now()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(set); err != nil {
		log.Printf("encode set response: %v", err)
	}
}

func (s *Server) handleGetSet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	set, err := s.getSetByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Set not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(set); err != nil {
		log.Printf("encode set response: %v", err)
	}
}

func (s *Server) handleUpdateSet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var set models.Set
	if err := json.NewDecoder(r.Body).Decode(&set); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, err = s.db.Conn().Exec(
		"UPDATE sets SET brand_id = ?, set_code = ?, name = ?, year = ?, piece_count = ?, minifigs = ?, theme = ?, image_url = ?, notes = ? WHERE id = ?",
		set.BrandID, set.SetCode, set.Name, set.Year, set.PieceCount, set.Minifigs,
		set.Theme, set.ImageURL, set.Notes, id,
	)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	set.ID = id
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(set); err != nil {
		log.Printf("encode set response: %v", err)
	}
}

func (s *Server) handleDeleteSet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	_, err = s.db.Conn().Exec("DELETE FROM sets WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListCollection(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	condition := strings.TrimSpace(r.URL.Query().Get("condition"))
	tagsInput := strings.TrimSpace(r.URL.Query().Get("tags"))
	filterTags := parseTagInput(tagsInput)

	items := s.getFilteredCollectionItems(status, condition, filterTags)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(items); err != nil {
		log.Printf("encode collection items response: %v", err)
	}
}

func (s *Server) handleCreateCollectionItem(w http.ResponseWriter, r *http.Request) {
	var item models.CollectionItem
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if !item.Condition.Valid() {
		http.Error(w, "Invalid condition", http.StatusBadRequest)
		return
	}

	if !item.Status.Valid() {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	result, err := s.db.Conn().Exec(
		"INSERT INTO collection_items (set_id, quantity, condition, location, purchase_price, purchase_date, missing_notes, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		item.SetID, item.Quantity, item.Condition, item.Location, item.PurchasePrice, item.PurchaseDate, item.MissingNotes, item.Status,
	)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	item.ID = id
	item.CreatedAt = time.Now()
	item.UpdatedAt = time.Now()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(item); err != nil {
		log.Printf("encode collection item response: %v", err)
	}
}

func (s *Server) handleUpdateCollectionItem(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var item models.CollectionItem
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if !item.Condition.Valid() {
		http.Error(w, "Invalid condition", http.StatusBadRequest)
		return
	}

	if !item.Status.Valid() {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	_, err = s.db.Conn().Exec(
		"UPDATE collection_items SET set_id = ?, quantity = ?, condition = ?, location = ?, purchase_price = ?, purchase_date = ?, missing_notes = ?, status = ? WHERE id = ?",
		item.SetID, item.Quantity, item.Condition, item.Location, item.PurchasePrice, item.PurchaseDate, item.MissingNotes, item.Status, id,
	)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	item.ID = id
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(item); err != nil {
		log.Printf("encode collection item response: %v", err)
	}
}

func (s *Server) handleDeleteCollectionItem(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	_, err = s.db.Conn().Exec("DELETE FROM collection_items WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRefreshValuation(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	set, err := s.getSetByID(id)
	if err != nil {
		http.Error(w, "Set not found", http.StatusNotFound)
		return
	}

	valuation, err := s.bricklinkPrice.GetInventoryAverage(r.Context(), set.SetCode, models.ConditionSealed)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if encodeErr := json.NewEncoder(w).Encode(map[string]string{
			"message": fmt.Sprintf("Failed to refresh valuation: %v", err),
			"status":  "error",
		}); encodeErr != nil {
			log.Printf("encode valuation error response: %v", encodeErr)
		}
		return
	}

	_, err = s.db.Conn().Exec(`
		INSERT INTO valuations (set_id, provider, currency, condition, metric, value, sample_size, confidence, as_of_date, raw_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, valuation.Provider, valuation.Currency, valuation.Condition, valuation.Metric, valuation.Value, valuation.SampleSize, valuation.Confidence, valuation.AsOfDate, valuation.RawJSON)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if encodeErr := json.NewEncoder(w).Encode(map[string]string{
			"message": fmt.Sprintf("Valuation fetched but failed to save: %v", err),
			"status":  "partial",
		}); encodeErr != nil {
			log.Printf("encode valuation partial response: %v", encodeErr)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   fmt.Sprintf("Valuation refreshed for set %d: %s %.2f", id, valuation.Currency, valuation.Value),
		"status":    "success",
		"valuation": valuation,
	}); err != nil {
		log.Printf("encode valuation success response: %v", err)
	}
}

func (s *Server) handleFetchSetMetadata(w http.ResponseWriter, r *http.Request) {
	setNum := strings.TrimSpace(chi.URLParam(r, "setNum"))
	if setNum == "" {
		http.Error(w, "Set number required", http.StatusBadRequest)
		return
	}

	result, err := s.fetchSetMetadata(r.Context(), setNum)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (s *Server) fetchSetMetadata(ctx context.Context, setNumber string) (map[string]interface{}, error) {
	setNumber = strings.TrimSpace(setNumber)
	if setNumber == "" {
		return nil, fmt.Errorf("set number required")
	}
	setNumber = normalizeSetCode(setNumber)

	var lastErr error
	if strings.TrimSpace(s.config.Providers.Brickset.APIKey) != "" {
		result, err := s.brickset.GetSetByNumber(ctx, setNumber)
		if err == nil {
			return map[string]interface{}{
				"set_code":    result.Number,
				"name":        result.Name,
				"year":        result.Year,
				"piece_count": result.Pieces,
				"minifigs":    result.Minifigs,
				"theme":       result.Theme,
				"image_url":   result.ImageURL,
			}, nil
		}
		lastErr = err
	}

	if strings.TrimSpace(s.config.Providers.Rebrickable.APIKey) != "" {
		result, err := s.rebrickable.GetSetByNumber(ctx, setNumber)
		if err == nil {
			return map[string]interface{}{
				"set_code":    result.SetNum,
				"name":        result.Name,
				"year":        result.Year,
				"piece_count": result.NumParts,
				"image_url":   result.SetImgURL,
			}, nil
		}
		lastErr = err
	}

	if s.bricklinkScrape != nil {
		result, err := s.bricklinkScrape.GetSetByNumber(ctx, setNumber)
		if err == nil {
			return map[string]interface{}{
				"set_code":    result.SetNumber,
				"name":        result.Name,
				"year":        result.Year,
				"piece_count": result.Pieces,
				"theme":       result.Theme,
				"image_url":   result.ImageURL,
			}, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		return nil, fmt.Errorf("no metadata providers available")
	}

	return nil, lastErr
}

func (s *Server) handleAPIListUsers(w http.ResponseWriter, r *http.Request) {
	users := s.listUsers()
	for i := range users {
		users[i].PasswordHash = ""
	}
	respondJSON(w, http.StatusOK, users)
}

func (s *Server) handleAPICreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"` // #nosec G117 -- request payload field.
		Role     string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	username := strings.TrimSpace(req.Username)
	role := normalizeRole(req.Role)
	if username == "" || req.Password == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_fields"})
		return
	}

	hash, err := s.hashPassword(req.Password)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "hash_failed"})
		return
	}

	if _, err := s.db.Conn().Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", username, hash, role); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "create_failed"})
		return
	}

	respondJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

func (s *Server) handleAPIUpdateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"` // #nosec G117 -- request payload field.
		Role     string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_id"})
		return
	}

	user, err := s.getUserByID(id)
	if err != nil {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = user.Username
	}
	role := normalizeRole(req.Role)

	if err := s.ensureCanChangeRole(id, user.Role, role); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if _, err := s.db.Conn().Exec("UPDATE users SET username = ?, role = ? WHERE id = ?", username, role, id); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "update_failed"})
		return
	}

	if req.Password != "" {
		hash, err := s.hashPassword(req.Password)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "hash_failed"})
			return
		}
		if _, err := s.db.Conn().Exec("UPDATE users SET password_hash = ? WHERE id = ?", hash, id); err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "update_failed"})
			return
		}
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleAPIDisableUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_id"})
		return
	}

	if err := s.ensureCanRemoveUser(id); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := s.disableUser(id); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "disable_failed"})
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}

func (s *Server) handleAPIEnableUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_id"})
		return
	}

	if _, err := s.db.Conn().Exec("UPDATE users SET disabled_at = NULL WHERE id = ?", id); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "enable_failed"})
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "enabled"})
}

func (s *Server) handleAPIDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_id"})
		return
	}

	if err := s.ensureCanRemoveUser(id); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if _, err := s.db.Conn().Exec("DELETE FROM users WHERE id = ?", id); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete_failed"})
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) Close() error {
	return s.db.Close()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

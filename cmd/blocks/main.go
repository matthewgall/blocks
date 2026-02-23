package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/matthewgall/blocks/internal/config"
	"github.com/matthewgall/blocks/internal/http/server"
)

var (
	configFile         = flag.String("config", "config.yaml", "Path to configuration file")
	version            = flag.Bool("version", false, "Show version information")
	serverAddress      = flag.String("address", "", "Server address (host:port)")
	serverHost         = flag.String("host", "", "Server host")
	serverPort         = flag.Int("port", 0, "Server port")
	databasePath       = flag.String("db-path", "", "Database path")
	authSecret         = flag.String("auth-secret", "", "Auth session secret")
	authBcryptCost     = flag.Int("auth-bcrypt-cost", 0, "Auth bcrypt cost")
	uploadsDir         = flag.String("uploads-dir", "", "Uploads directory")
	uploadsMaxSize     = flag.Int64("uploads-max-size", 0, "Uploads max size (bytes)")
	appNameFlag        = flag.String("app-name", "", "Application name")
	defaultCurrency    = flag.String("default-currency", "", "Default currency")
	embedAssets        = flag.Bool("embed-assets", true, "Embed templates and static assets")
	bricksetAPIKey     = flag.String("brickset-api-key", "", "Brickset API key")
	bricksetDailyLimit = flag.Int("brickset-daily-limit", 0, "Brickset daily limit")
	rebrickableAPIKey  = flag.String("rebrickable-api-key", "", "Rebrickable API key")
	cacheDefaultTTL    = flag.Duration("cache-ttl-default", 0, "Cache default TTL")
	cacheRemoteTTL     = flag.Duration("cache-ttl-remote", 0, "Cache remote provider TTL")
	cacheDir           = flag.String("cache-dir", "", "Cache directory")
)

const (
	appName    = "Blocks"
	appVersion = "1.0.0"
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("%s v%s\n", appName, appVersion)
		os.Exit(0)
	}

	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	overrides := config.Overrides{}
	if *serverAddress != "" {
		overrides.ServerAddress = serverAddress
	} else if *serverHost != "" || *serverPort != 0 {
		host, port := splitAddress(cfg.Server.Address)
		if *serverHost != "" {
			host = *serverHost
		}
		if *serverPort != 0 {
			port = fmt.Sprintf("%d", *serverPort)
		}
		if host == "" {
			host = "0.0.0.0"
		}
		if port == "" {
			port = "8080"
		}
		address := fmt.Sprintf("%s:%s", host, port)
		overrides.ServerAddress = &address
	}
	if *databasePath != "" {
		overrides.DatabasePath = databasePath
	}
	if *authSecret != "" {
		overrides.AuthSessionSecret = authSecret
	}
	if *authBcryptCost != 0 {
		overrides.AuthBcryptCost = authBcryptCost
	}
	if *uploadsDir != "" {
		overrides.UploadsDirectory = uploadsDir
	}
	if *uploadsMaxSize != 0 {
		overrides.UploadsMaxSize = uploadsMaxSize
	}
	if *appNameFlag != "" {
		overrides.AppName = appNameFlag
	}
	if *defaultCurrency != "" {
		overrides.AppDefaultCurrency = defaultCurrency
	}
	overrides.AppEmbedAssets = embedAssets
	if *bricksetAPIKey != "" {
		overrides.BricksetAPIKey = bricksetAPIKey
	}
	if *bricksetDailyLimit != 0 {
		overrides.BricksetDailyLimit = bricksetDailyLimit
	}
	if *rebrickableAPIKey != "" {
		overrides.RebrickableAPIKey = rebrickableAPIKey
	}
	if *cacheDefaultTTL != 0 {
		overrides.CacheTTLDefault = cacheDefaultTTL
	}
	if *cacheRemoteTTL != 0 {
		overrides.CacheTTLRemote = cacheRemoteTTL
	}
	if *cacheDir != "" {
		overrides.CacheDirectory = cacheDir
	}

	if err := cfg.ApplyOverrides(overrides); err != nil {
		log.Fatalf("Failed to apply overrides: %v", err)
	}

	srv := server.New(cfg)

	server := &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      srv,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	go func() {
		log.Printf("Starting %s server on %s", appName, cfg.Server.Address)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

func splitAddress(address string) (string, string) {
	if address == "" {
		return "", ""
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", ""
	}
	return host, port
}

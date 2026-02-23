package config

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Database  DatabaseConfig  `yaml:"database"`
	Auth      AuthConfig      `yaml:"auth"`
	Uploads   UploadsConfig   `yaml:"uploads"`
	Providers ProvidersConfig `yaml:"providers"`
	Cache     CacheConfig     `yaml:"cache"`
	App       AppConfig       `yaml:"app"`
}

type ServerConfig struct {
	Address      string        `yaml:"address"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type AuthConfig struct {
	SessionSecret string `yaml:"session_secret"` // #nosec G117 -- configuration secret field.
	BcryptCost    int    `yaml:"bcrypt_cost"`
}

type UploadsConfig struct {
	Method  string             `yaml:"method"`
	MaxSize int64              `yaml:"max_size"`
	Local   UploadsLocalConfig `yaml:"local"`
	S3      UploadsS3Config    `yaml:"s3"`
}

type UploadsLocalConfig struct {
	Directory string `yaml:"directory"`
}

type UploadsS3Config struct {
	Bucket          string `yaml:"bucket"`
	Region          string `yaml:"region"`
	Endpoint        string `yaml:"endpoint"`
	PublicURL       string `yaml:"public_url"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	SessionToken    string `yaml:"session_token"` // #nosec G117 -- configuration secret field.
	Prefix          string `yaml:"prefix"`
	PathStyle       bool   `yaml:"path_style"`
}

type ProvidersConfig struct {
	Brickset    BricksetConfig    `yaml:"brickset"`
	Rebrickable RebrickableConfig `yaml:"rebrickable"`
}

type BricksetConfig struct {
	APIKey     string `yaml:"api_key"` // #nosec G117 -- configuration secret field.
	DailyLimit int    `yaml:"daily_limit"`
}

type RebrickableConfig struct {
	APIKey string `yaml:"api_key"` // #nosec G117 -- configuration secret field.
}

type CacheConfig struct {
	Provider  string           `yaml:"provider"`
	Directory string           `yaml:"directory"`
	TTL       CacheTTLConfig   `yaml:"ttl"`
	Redis     CacheRedisConfig `yaml:"redis"`
}

type CacheTTLConfig struct {
	Default time.Duration `yaml:"default"`
	Remote  time.Duration `yaml:"remote"`
}

type CacheRedisConfig struct {
	URL      string `yaml:"url"`
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"` // #nosec G117 -- configuration secret field.
	DB       int    `yaml:"db"`
	UseTLS   bool   `yaml:"tls"`
}

type AppConfig struct {
	Name            string `yaml:"name"`
	DefaultCurrency string `yaml:"default_currency"`
	EmbedAssets     bool   `yaml:"embed_assets"`
}

func Load(path string) (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Address:      ":8080",
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		Database: DatabaseConfig{
			Path: "data/blocks.db",
		},
		Auth: AuthConfig{
			SessionSecret: "change-me-in-production",
			BcryptCost:    12,
		},
		Uploads: UploadsConfig{
			Method:  "local",
			MaxSize: 10 * 1024 * 1024, // 10MB
			Local: UploadsLocalConfig{
				Directory: "data/uploads",
			},
		},
		Cache: CacheConfig{
			Provider: "sqlite",
			TTL: CacheTTLConfig{
				Default: 24 * time.Hour,
				Remote:  30 * 24 * time.Hour, // 30 days
			},
		},
		App: AppConfig{
			Name:            "Blocks",
			DefaultCurrency: "GBP",
			EmbedAssets:     true,
		},
	}

	root, err := os.OpenRoot(filepath.Dir(path))
	if err == nil {
		defer root.Close()
		if _, err := root.Stat(filepath.Base(path)); err == nil {
			file, err := root.Open(filepath.Base(path))
			if err != nil {
				return nil, fmt.Errorf("reading config file: %w", err)
			}
			defer file.Close()
			data, err := io.ReadAll(file)
			if err != nil {
				return nil, fmt.Errorf("reading config file: %w", err)
			}

			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("parsing config file: %w", err)
			}
		}
	}

	if err := cfg.applyEnv(); err != nil {
		return nil, fmt.Errorf("applying env: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

type Overrides struct {
	ServerAddress      *string
	ServerReadTimeout  *time.Duration
	ServerWriteTimeout *time.Duration
	ServerIdleTimeout  *time.Duration
	DatabasePath       *string
	AuthSessionSecret  *string
	AuthBcryptCost     *int
	UploadsDirectory   *string
	UploadsMaxSize     *int64
	UploadsMethod      *string
	UploadsLocalDir    *string
	UploadsS3Bucket    *string
	UploadsS3Region    *string
	UploadsS3Endpoint  *string
	UploadsS3PublicURL *string
	UploadsS3AccessKey *string
	UploadsS3SecretKey *string
	UploadsS3Session   *string
	UploadsS3Prefix    *string
	UploadsS3PathStyle *bool
	AppName            *string
	AppDefaultCurrency *string
	AppEmbedAssets     *bool
	BricksetAPIKey     *string
	BricksetDailyLimit *int
	RebrickableAPIKey  *string
	CacheTTLDefault    *time.Duration
	CacheTTLRemote     *time.Duration
	CacheDirectory     *string
	CacheProvider      *string
	CacheRedisURL      *string
	CacheRedisAddr     *string
	CacheRedisPassword *string
	CacheRedisDB       *int
	CacheRedisTLS      *bool
}

func (c *Config) ApplyOverrides(overrides Overrides) error {
	if overrides.ServerAddress != nil {
		c.Server.Address = *overrides.ServerAddress
	}
	if overrides.ServerReadTimeout != nil {
		c.Server.ReadTimeout = *overrides.ServerReadTimeout
	}
	if overrides.ServerWriteTimeout != nil {
		c.Server.WriteTimeout = *overrides.ServerWriteTimeout
	}
	if overrides.ServerIdleTimeout != nil {
		c.Server.IdleTimeout = *overrides.ServerIdleTimeout
	}
	if overrides.DatabasePath != nil {
		c.Database.Path = *overrides.DatabasePath
	}
	if overrides.AuthSessionSecret != nil {
		c.Auth.SessionSecret = *overrides.AuthSessionSecret
	}
	if overrides.AuthBcryptCost != nil {
		c.Auth.BcryptCost = *overrides.AuthBcryptCost
	}
	if overrides.UploadsDirectory != nil {
		c.Uploads.Local.Directory = *overrides.UploadsDirectory
	}
	if overrides.UploadsMaxSize != nil {
		c.Uploads.MaxSize = *overrides.UploadsMaxSize
	}
	if overrides.UploadsMethod != nil {
		c.Uploads.Method = *overrides.UploadsMethod
	}
	if overrides.UploadsLocalDir != nil {
		c.Uploads.Local.Directory = *overrides.UploadsLocalDir
	}
	if overrides.UploadsS3Bucket != nil {
		c.Uploads.S3.Bucket = *overrides.UploadsS3Bucket
	}
	if overrides.UploadsS3Region != nil {
		c.Uploads.S3.Region = *overrides.UploadsS3Region
	}
	if overrides.UploadsS3Endpoint != nil {
		c.Uploads.S3.Endpoint = *overrides.UploadsS3Endpoint
	}
	if overrides.UploadsS3PublicURL != nil {
		c.Uploads.S3.PublicURL = *overrides.UploadsS3PublicURL
	}
	if overrides.UploadsS3AccessKey != nil {
		c.Uploads.S3.AccessKeyID = *overrides.UploadsS3AccessKey
	}
	if overrides.UploadsS3SecretKey != nil {
		c.Uploads.S3.SecretAccessKey = *overrides.UploadsS3SecretKey
	}
	if overrides.UploadsS3Session != nil {
		c.Uploads.S3.SessionToken = *overrides.UploadsS3Session
	}
	if overrides.UploadsS3Prefix != nil {
		c.Uploads.S3.Prefix = *overrides.UploadsS3Prefix
	}
	if overrides.UploadsS3PathStyle != nil {
		c.Uploads.S3.PathStyle = *overrides.UploadsS3PathStyle
	}
	if overrides.AppName != nil {
		c.App.Name = *overrides.AppName
	}
	if overrides.AppDefaultCurrency != nil {
		c.App.DefaultCurrency = *overrides.AppDefaultCurrency
	}
	if overrides.AppEmbedAssets != nil {
		c.App.EmbedAssets = *overrides.AppEmbedAssets
	}
	if overrides.BricksetAPIKey != nil {
		c.Providers.Brickset.APIKey = *overrides.BricksetAPIKey
	}
	if overrides.BricksetDailyLimit != nil {
		c.Providers.Brickset.DailyLimit = *overrides.BricksetDailyLimit
	}
	if overrides.RebrickableAPIKey != nil {
		c.Providers.Rebrickable.APIKey = *overrides.RebrickableAPIKey
	}
	if overrides.CacheTTLDefault != nil {
		c.Cache.TTL.Default = *overrides.CacheTTLDefault
	}
	if overrides.CacheTTLRemote != nil {
		c.Cache.TTL.Remote = *overrides.CacheTTLRemote
	}
	if overrides.CacheDirectory != nil {
		c.Cache.Directory = *overrides.CacheDirectory
	}
	if overrides.CacheProvider != nil {
		c.Cache.Provider = *overrides.CacheProvider
	}
	if overrides.CacheRedisURL != nil {
		c.Cache.Redis.URL = *overrides.CacheRedisURL
	}
	if overrides.CacheRedisAddr != nil {
		c.Cache.Redis.Addr = *overrides.CacheRedisAddr
	}
	if overrides.CacheRedisPassword != nil {
		c.Cache.Redis.Password = *overrides.CacheRedisPassword
	}
	if overrides.CacheRedisDB != nil {
		c.Cache.Redis.DB = *overrides.CacheRedisDB
	}
	if overrides.CacheRedisTLS != nil {
		c.Cache.Redis.UseTLS = *overrides.CacheRedisTLS
	}

	return c.validate()
}

func (c *Config) applyEnv() error {
	addressSet := false
	if value, ok := lookupEnv("BLOCKS_SERVER_ADDRESS"); ok {
		c.Server.Address = value
		addressSet = true
	}
	serverHost, hostSet := lookupEnv("BLOCKS_SERVER_HOST")
	serverPort, portSet := lookupEnv("BLOCKS_SERVER_PORT")
	if value, ok := lookupEnv("IP"); ok && !hostSet {
		serverHost = value
		hostSet = true
	}
	if value, ok := lookupEnv("HOST"); ok && !hostSet {
		serverHost = value
		hostSet = true
	}
	if value, ok := lookupEnv("PORT"); ok && !portSet {
		serverPort = value
		portSet = true
	}
	if !addressSet && (hostSet || portSet) {
		if serverHost == "" {
			serverHost = "0.0.0.0"
		}
		if serverPort == "" {
			serverPort = "8080"
		}
		c.Server.Address = fmt.Sprintf("%s:%s", serverHost, serverPort)
	}
	if value, ok := lookupEnv("BLOCKS_SERVER_READ_TIMEOUT"); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("BLOCKS_SERVER_READ_TIMEOUT: %w", err)
		}
		c.Server.ReadTimeout = duration
	}
	if value, ok := lookupEnv("BLOCKS_SERVER_WRITE_TIMEOUT"); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("BLOCKS_SERVER_WRITE_TIMEOUT: %w", err)
		}
		c.Server.WriteTimeout = duration
	}
	if value, ok := lookupEnv("BLOCKS_SERVER_IDLE_TIMEOUT"); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("BLOCKS_SERVER_IDLE_TIMEOUT: %w", err)
		}
		c.Server.IdleTimeout = duration
	}
	if value, ok := lookupEnv("BLOCKS_DATABASE_PATH"); ok {
		c.Database.Path = value
	}
	if value, ok := lookupEnv("BLOCKS_AUTH_SESSION_SECRET"); ok {
		c.Auth.SessionSecret = value
	}
	if value, ok := lookupEnv("BLOCKS_AUTH_BCRYPT_COST"); ok {
		parsed, err := parseInt(value)
		if err != nil {
			return fmt.Errorf("BLOCKS_AUTH_BCRYPT_COST: %w", err)
		}
		c.Auth.BcryptCost = parsed
	}
	if value, ok := lookupEnv("BLOCKS_UPLOADS_METHOD"); ok {
		c.Uploads.Method = value
	} else if value, ok := lookupEnv("BLOCKS_UPLOADS_STORAGE"); ok {
		c.Uploads.Method = value
	}
	if value, ok := lookupEnv("BLOCKS_UPLOADS_LOCAL_DIRECTORY"); ok {
		c.Uploads.Local.Directory = value
	} else if value, ok := lookupEnv("BLOCKS_UPLOADS_DIRECTORY"); ok {
		c.Uploads.Local.Directory = value
	}
	if value, ok := lookupEnv("BLOCKS_UPLOADS_MAX_SIZE"); ok {
		parsed, err := parseInt64(value)
		if err != nil {
			return fmt.Errorf("BLOCKS_UPLOADS_MAX_SIZE: %w", err)
		}
		c.Uploads.MaxSize = parsed
	}
	if value, ok := lookupEnv("BLOCKS_UPLOADS_S3_BUCKET"); ok {
		c.Uploads.S3.Bucket = value
	}
	if value, ok := lookupEnv("BLOCKS_UPLOADS_S3_REGION"); ok {
		c.Uploads.S3.Region = value
	}
	if value, ok := lookupEnv("BLOCKS_UPLOADS_S3_ENDPOINT"); ok {
		c.Uploads.S3.Endpoint = value
	}
	if value, ok := lookupEnv("BLOCKS_UPLOADS_S3_PUBLIC_URL"); ok {
		c.Uploads.S3.PublicURL = value
	}
	if value, ok := lookupEnv("BLOCKS_UPLOADS_S3_ACCESS_KEY_ID"); ok {
		c.Uploads.S3.AccessKeyID = value
	}
	if value, ok := lookupEnv("BLOCKS_UPLOADS_S3_SECRET_ACCESS_KEY"); ok {
		c.Uploads.S3.SecretAccessKey = value
	}
	if value, ok := lookupEnv("BLOCKS_UPLOADS_S3_SESSION_TOKEN"); ok {
		c.Uploads.S3.SessionToken = value
	}
	if value, ok := lookupEnv("BLOCKS_UPLOADS_S3_PREFIX"); ok {
		c.Uploads.S3.Prefix = value
	}
	if value, ok := lookupEnv("BLOCKS_UPLOADS_S3_PATH_STYLE"); ok {
		parsed, err := parseBool(value)
		if err != nil {
			return fmt.Errorf("BLOCKS_UPLOADS_S3_PATH_STYLE: %w", err)
		}
		c.Uploads.S3.PathStyle = parsed
	}
	if value, ok := lookupEnv("BLOCKS_APP_NAME"); ok {
		c.App.Name = value
	}
	if value, ok := lookupEnv("BLOCKS_APP_DEFAULT_CURRENCY"); ok {
		c.App.DefaultCurrency = value
	}
	if value, ok := lookupEnv("BLOCKS_APP_EMBED_ASSETS"); ok {
		parsed, err := parseBool(value)
		if err != nil {
			return fmt.Errorf("BLOCKS_APP_EMBED_ASSETS: %w", err)
		}
		c.App.EmbedAssets = parsed
	}
	if value, ok := lookupEnv("BLOCKS_PROVIDER_BRICKSET_API_KEY"); ok {
		c.Providers.Brickset.APIKey = value
	}
	if value, ok := lookupEnv("BLOCKS_PROVIDER_BRICKSET_DAILY_LIMIT"); ok {
		parsed, err := parseInt(value)
		if err != nil {
			return fmt.Errorf("BLOCKS_PROVIDER_BRICKSET_DAILY_LIMIT: %w", err)
		}
		c.Providers.Brickset.DailyLimit = parsed
	}
	if value, ok := lookupEnv("BLOCKS_PROVIDER_REBRICKABLE_API_KEY"); ok {
		c.Providers.Rebrickable.APIKey = value
	}
	if value, ok := lookupEnv("BLOCKS_CACHE_TTL_DEFAULT"); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("BLOCKS_CACHE_TTL_DEFAULT: %w", err)
		}
		c.Cache.TTL.Default = duration
	}
	if value, ok := lookupEnv("BLOCKS_CACHE_TTL_REMOTE"); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("BLOCKS_CACHE_TTL_REMOTE: %w", err)
		}
		c.Cache.TTL.Remote = duration
	}
	if value, ok := lookupEnv("BLOCKS_CACHE_PROVIDER"); ok {
		c.Cache.Provider = value
	}
	if value, ok := lookupEnv("BLOCKS_CACHE_REDIS_URL"); ok {
		c.Cache.Redis.URL = value
	} else if value, ok := lookupEnv("REDIS_URL"); ok {
		c.Cache.Redis.URL = value
	}
	if value, ok := lookupEnv("BLOCKS_CACHE_REDIS_ADDR"); ok {
		c.Cache.Redis.Addr = value
	}
	if value, ok := lookupEnv("BLOCKS_CACHE_REDIS_PASSWORD"); ok {
		c.Cache.Redis.Password = value
	}
	if value, ok := lookupEnv("BLOCKS_CACHE_REDIS_DB"); ok {
		parsed, err := parseInt(value)
		if err != nil {
			return fmt.Errorf("BLOCKS_CACHE_REDIS_DB: %w", err)
		}
		c.Cache.Redis.DB = parsed
	}
	if value, ok := lookupEnv("BLOCKS_CACHE_REDIS_TLS"); ok {
		parsed, err := parseBool(value)
		if err != nil {
			return fmt.Errorf("BLOCKS_CACHE_REDIS_TLS: %w", err)
		}
		c.Cache.Redis.UseTLS = parsed
	}
	if value, ok := lookupEnv("BLOCKS_CACHE_DIRECTORY"); ok {
		c.Cache.Directory = value
	}
	if strings.TrimSpace(c.Cache.Redis.URL) != "" {
		if err := applyRedisURL(&c.Cache.Redis); err != nil {
			return err
		}
	}

	return nil
}

func lookupEnv(key string) (string, bool) {
	value, ok := os.LookupEnv(key)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	return value, true
}

func parseInt(value string) (int, error) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, err
	}
	return parsed, nil
}

func parseInt64(value string) (int64, error) {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0, err
	}
	return parsed, nil
}

func parseBool(value string) (bool, error) {
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false, err
	}
	return parsed, nil
}

func applyRedisURL(cfg *CacheRedisConfig) error {
	if cfg == nil {
		return nil
	}
	raw := strings.TrimSpace(cfg.URL)
	if raw == "" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("cache redis url: %w", err)
	}
	if parsed.Host == "" {
		return fmt.Errorf("cache redis url: missing host")
	}
	if parsed.User != nil {
		password, ok := parsed.User.Password()
		if ok {
			cfg.Password = password
		}
	}
	path := strings.Trim(parsed.Path, "/")
	if path != "" {
		if dbIndex, err := strconv.Atoi(path); err == nil {
			cfg.DB = dbIndex
		} else {
			return fmt.Errorf("cache redis url: invalid db index")
		}
	}
	query := parsed.Query()
	if value := strings.TrimSpace(query.Get("db")); value != "" {
		if dbIndex, err := strconv.Atoi(value); err == nil {
			cfg.DB = dbIndex
		} else {
			return fmt.Errorf("cache redis url: invalid db query param")
		}
	}
	if value := strings.ToLower(strings.TrimSpace(query.Get("ssl"))); value != "" {
		parsedBool, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("cache redis url: invalid ssl query param")
		}
		cfg.UseTLS = parsedBool
	}
	if value := strings.ToLower(strings.TrimSpace(query.Get("tls"))); value != "" {
		parsedBool, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("cache redis url: invalid tls query param")
		}
		cfg.UseTLS = parsedBool
	}
	if value := strings.ToLower(strings.TrimSpace(query.Get("sslmode"))); value != "" {
		if value == "require" || value == "verify-full" || value == "verify-ca" {
			cfg.UseTLS = true
		} else if value == "disable" {
			cfg.UseTLS = false
		}
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "rediss" {
		cfg.UseTLS = true
	}
	if cfg.Addr == "" {
		cfg.Addr = parsed.Host
	}
	return nil
}

func (c *Config) validate() error {
	if c.Server.Address == "" {
		return fmt.Errorf("server address is required")
	}

	if c.Database.Path == "" {
		return fmt.Errorf("database path is required")
	}

	if c.Auth.SessionSecret == "" || c.Auth.SessionSecret == "change-me-in-production" {
		if os.Getenv("BLOCKS_ENV") == "production" {
			return fmt.Errorf("session secret must be set in production")
		}
	}

	method := strings.ToLower(strings.TrimSpace(c.Uploads.Method))
	if method == "" {
		method = "local"
		c.Uploads.Method = method
	}
	if method != "local" && method != "s3" {
		return fmt.Errorf("uploads method must be local or s3")
	}
	if method == "local" {
		if c.Uploads.Local.Directory == "" {
			return fmt.Errorf("uploads local directory is required")
		}
	}
	if method == "s3" {
		if strings.TrimSpace(c.Uploads.S3.Bucket) == "" {
			return fmt.Errorf("uploads s3 bucket is required")
		}
		if strings.TrimSpace(c.Uploads.S3.Region) == "" {
			return fmt.Errorf("uploads s3 region is required")
		}
		if strings.TrimSpace(c.Uploads.S3.PublicURL) != "" {
			parsed, err := url.Parse(c.Uploads.S3.PublicURL)
			if err != nil || parsed.Host == "" {
				return fmt.Errorf("uploads s3 public url must be a valid url")
			}
			scheme := strings.ToLower(parsed.Scheme)
			if scheme != "http" && scheme != "https" {
				return fmt.Errorf("uploads s3 public url must use http or https")
			}
		}
	}

	cacheProvider := strings.ToLower(strings.TrimSpace(c.Cache.Provider))
	if cacheProvider == "" {
		cacheProvider = "sqlite"
		c.Cache.Provider = cacheProvider
	}
	if cacheProvider != "sqlite" && cacheProvider != "redis" {
		return fmt.Errorf("cache provider must be sqlite or redis")
	}
	if cacheProvider == "redis" {
		if strings.TrimSpace(c.Cache.Redis.Addr) == "" {
			return fmt.Errorf("cache redis addr is required")
		}
	}
	if c.Cache.TTL.Default <= 0 {
		c.Cache.TTL.Default = 24 * time.Hour
	}
	if c.Cache.TTL.Remote <= 0 {
		c.Cache.TTL.Remote = 30 * 24 * time.Hour
	}

	return nil
}

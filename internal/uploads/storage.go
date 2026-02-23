package uploads

import (
	"context"
	"errors"
	"io"
	"net/url"
	"path"
	"strings"

	"github.com/matthewgall/blocks/internal/config"
)

var ErrUnknownStorage = errors.New("unknown uploads storage")

type Storage interface {
	Save(ctx context.Context, key string, body io.Reader) error
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
}

// PublicURL returns a public URL for the key when supported by config.
// It returns false when uploads are not configured with a public URL.
func PublicURL(cfg config.UploadsConfig, key string) (string, bool) {
	method := strings.ToLower(strings.TrimSpace(cfg.Method))
	if method != "s3" {
		return "", false
	}
	base := strings.TrimSpace(cfg.S3.PublicURL)
	if base == "" {
		return "", false
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	key = strings.TrimLeft(key, "/")
	prefix := strings.Trim(cfg.S3.Prefix, "/")
	if prefix != "" {
		key = path.Join(prefix, key)
	}
	parsed.Path = path.Join(parsed.Path, key)
	return parsed.String(), true
}

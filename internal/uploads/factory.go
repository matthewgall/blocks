package uploads

import (
	"context"
	"strings"

	"github.com/matthewgall/blocks/internal/config"
)

func New(ctx context.Context, cfg config.UploadsConfig) (Storage, error) {
	method := strings.ToLower(strings.TrimSpace(cfg.Method))
	switch method {
	case "", "local":
		baseDir := strings.TrimSpace(cfg.Local.Directory)
		if baseDir == "" {
			baseDir = "data/uploads"
		}
		return NewLocal(baseDir), nil
	case "s3":
		return NewS3(ctx, cfg.S3)
	default:
		return nil, ErrUnknownStorage
	}
}

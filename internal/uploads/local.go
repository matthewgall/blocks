package uploads

import (
	"context"
	"io"
	"os"
	"path/filepath"
)

type LocalStorage struct {
	baseDir string
}

func NewLocal(baseDir string) *LocalStorage {
	return &LocalStorage{baseDir: baseDir}
}

func (l *LocalStorage) Save(_ context.Context, key string, body io.Reader) error {
	path := l.pathForKey(key)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, body)
	return err
}

func (l *LocalStorage) Open(_ context.Context, key string) (io.ReadCloser, error) {
	return os.Open(l.pathForKey(key))
}

func (l *LocalStorage) Delete(_ context.Context, key string) error {
	path := l.pathForKey(key)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return nil
}

func (l *LocalStorage) pathForKey(key string) string {
	return filepath.Join(l.baseDir, filepath.FromSlash(key))
}

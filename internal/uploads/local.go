package uploads

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type LocalStorage struct {
	baseDir string
}

func NewLocal(baseDir string) *LocalStorage {
	return &LocalStorage{baseDir: baseDir}
}

func (l *LocalStorage) Save(_ context.Context, key string, body io.Reader) error {
	relative := filepath.FromSlash(key)
	root, err := os.OpenRoot(l.baseDir)
	if err != nil {
		return err
	}
	defer root.Close()

	if err := mkdirAllRoot(root, filepath.Dir(relative), 0o750); err != nil {
		return err
	}
	file, err := root.OpenFile(relative, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, body)
	return err
}

func (l *LocalStorage) Open(_ context.Context, key string) (io.ReadCloser, error) {
	root, err := os.OpenRoot(l.baseDir)
	if err != nil {
		return nil, err
	}
	file, err := root.Open(filepath.FromSlash(key))
	if err != nil {
		if closeErr := root.Close(); closeErr != nil {
			return nil, closeErr
		}
		return nil, err
	}
	return &rootReadCloser{root: root, file: file}, nil
}

func (l *LocalStorage) Delete(_ context.Context, key string) error {
	root, err := os.OpenRoot(l.baseDir)
	if err != nil {
		return err
	}
	defer root.Close()

	if err := root.Remove(filepath.FromSlash(key)); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return nil
}

func mkdirAllRoot(root *os.Root, dir string, perm os.FileMode) error {
	clean := filepath.Clean(dir)
	if clean == "." || clean == string(filepath.Separator) {
		return nil
	}
	parts := strings.Split(clean, string(filepath.Separator))
	current := ""
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if current == "" {
			current = part
		} else {
			current = filepath.Join(current, part)
		}
		if err := root.Mkdir(current, perm); err != nil {
			if !os.IsExist(err) {
				return err
			}
		}
	}
	return nil
}

type rootReadCloser struct {
	root *os.Root
	file *os.File
}

func (r *rootReadCloser) Read(p []byte) (int, error) {
	return r.file.Read(p)
}

func (r *rootReadCloser) Close() error {
	if err := r.file.Close(); err != nil {
		_ = r.root.Close()
		return err
	}
	return r.root.Close()
}

package waterlinkqa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type FileAccountStore struct {
	path string
	mu   sync.Mutex
}

func NewFileAccountStore(path string) (*FileAccountStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("account store path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("creating account store directory: %w", err)
	}
	return &FileAccountStore{path: path}, nil
}

func (s *FileAccountStore) CreateAccount(ctx context.Context, account Account) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	accounts, err := s.readAccounts()
	if err != nil {
		return err
	}
	for _, existing := range accounts {
		if strings.EqualFold(existing.Email, account.Email) {
			return ErrDuplicateEmail
		}
	}

	accounts = append(accounts, account)
	data, err := json.Marshal(accounts)
	if err != nil {
		return fmt.Errorf("encoding accounts: %w", err)
	}

	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".waterlink-accounts-*")
	if err != nil {
		return fmt.Errorf("creating temporary account store: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)

	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return fmt.Errorf("securing temporary account store: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("writing account store: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("syncing account store: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("closing account store: %w", err)
	}
	if err := os.Rename(temporaryName, s.path); err != nil {
		return fmt.Errorf("committing account store: %w", err)
	}
	return nil
}

func (s *FileAccountStore) readAccounts() ([]Account, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading account store: %w", err)
	}

	var accounts []Account
	if err := json.Unmarshal(data, &accounts); err != nil {
		return nil, fmt.Errorf("decoding account store: %w", err)
	}
	return accounts, nil
}
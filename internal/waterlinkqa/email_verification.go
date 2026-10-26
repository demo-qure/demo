package waterlinkqa

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	ledger "github.com/formancehq/ledger/internal"
)

var (
	ErrAccountNotFound          = errors.New("account not found")
	ErrInvalidVerificationToken = errors.New("invalid, expired, or used verification token")
	ErrInvalidTokenLifetime     = errors.New("verification token lifetime must be positive")
)

type accountFile struct {
	Accounts []accountRecord `json:"accounts"`
}

type accountRecord struct {
	Account       ledger.Account `json:"account"`
	TokenHash     []byte         `json:"emailVerificationTokenHash,omitempty"`
	TokenExpires  int64          `json:"emailVerificationExpiresAtUtcMs,omitempty"`
	TokenConsumed bool           `json:"emailVerificationTokenUsed,omitempty"`
}

type AccountStore struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
}

func NewAccountStore(path string) *AccountStore {
	return &AccountStore{
		path: path,
		now:  time.Now,
	}
}

func (s *AccountStore) Put(account ledger.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := s.read()
	if err != nil {
		return err
	}

	for i := range file.Accounts {
		if file.Accounts[i].Account.Address == account.Address {
			copyVerificationState(&account, file.Accounts[i])
			file.Accounts[i].Account = account
			return s.write(file)
		}
	}

	file.Accounts = append(file.Accounts, recordFromAccount(account))
	return s.write(file)
}

func (s *AccountStore) Get(address string) (ledger.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := s.read()
	if err != nil {
		return ledger.Account{}, err
	}
	for _, record := range file.Accounts {
		if record.Account.Address == address {
			return accountFromRecord(record), nil
		}
	}
	return ledger.Account{}, ErrAccountNotFound
}

func (s *AccountStore) IssueEmailVerificationToken(address string, lifetime time.Duration) (string, error) {
	if lifetime <= 0 {
		return "", ErrInvalidTokenLifetime
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate verification token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(token))

	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := s.read()
	if err != nil {
		return "", err
	}
	for i := range file.Accounts {
		if file.Accounts[i].Account.Address != address {
			continue
		}

		file.Accounts[i].TokenHash = append([]byte(nil), hash[:]...)
		file.Accounts[i].TokenExpires = s.now().UTC().Add(lifetime).UnixMilli()
		file.Accounts[i].TokenConsumed = false
		file.Accounts[i].Account.EmailVerified = false
		if err := s.write(file); err != nil {
			return "", err
		}
		return token, nil
	}
	return "", ErrAccountNotFound
}

func (s *AccountStore) VerifyEmail(token string) (ledger.Account, error) {
	hash := sha256.Sum256([]byte(token))

	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := s.read()
	if err != nil {
		return ledger.Account{}, err
	}

	for i := range file.Accounts {
		record := &file.Accounts[i]
		if len(record.TokenHash) != len(hash) ||
			subtle.ConstantTimeCompare(record.TokenHash, hash[:]) != 1 {
			continue
		}

		if record.TokenConsumed ||
			record.TokenExpires == 0 ||
			s.now().UTC().UnixMilli() >= record.TokenExpires {
			return accountFromRecord(*record), ErrInvalidVerificationToken
		}

		record.TokenConsumed = true
		record.Account.EmailVerified = true
		if err := s.write(file); err != nil {
			return ledger.Account{}, err
		}
		return accountFromRecord(*record), nil
	}

	return ledger.Account{}, ErrInvalidVerificationToken
}

func (s *AccountStore) read() (accountFile, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return accountFile{}, nil
	}
	if err != nil {
		return accountFile{}, fmt.Errorf("read account store: %w", err)
	}

	var file accountFile
	if err := json.Unmarshal(data, &file); err != nil {
		return accountFile{}, fmt.Errorf("decode account store: %w", err)
	}
	return file, nil
}

func (s *AccountStore) write(file accountFile) error {
	data, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("encode account store: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create account store directory: %w", err)
	}

	temporary, err := os.CreateTemp(dir, ".waterlink-accounts-*")
	if err != nil {
		return fmt.Errorf("create temporary account store: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return fmt.Errorf("restrict account store permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary account store: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary account store: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary account store: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace account store: %w", err)
	}
	return nil
}

func recordFromAccount(account ledger.Account) accountRecord {
	return accountRecord{
		Account:       account,
		TokenHash:     append([]byte(nil), account.EmailVerificationTokenHash...),
		TokenExpires:  account.EmailVerificationExpiresAtUTC,
		TokenConsumed: account.EmailVerificationTokenUsed,
	}
}

func accountFromRecord(record accountRecord) ledger.Account {
	account := record.Account
	copyVerificationState(&account, record)
	return account
}

func copyVerificationState(account *ledger.Account, record accountRecord) {
	account.EmailVerificationTokenHash = append([]byte(nil), record.TokenHash...)
	account.EmailVerificationExpiresAtUTC = record.TokenExpires
	account.EmailVerificationTokenUsed = record.TokenConsumed
}
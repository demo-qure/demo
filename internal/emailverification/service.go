package emailverification

import (
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode"
)

type AccountType string

const (
	AccountTypeClient   AccountType = "CLIENT"
	AccountTypeProvider AccountType = "PROVIDER"
)

type Outcome string

const (
	OutcomeSuccess        Outcome = "SUCCESS"
	OutcomeInvalid        Outcome = "INVALID"
	OutcomeExpired        Outcome = "EXPIRED"
	OutcomeReplay         Outcome = "REPLAY"
	OutcomeConcurrentLoss Outcome = "CONCURRENT_LOSS"
)

var (
	ErrInvalidAccountType = errors.New("account type must be CLIENT or PROVIDER")
	ErrInvalidToken       = errors.New("invalid verification token")
	ErrDuplicateAccount   = errors.New("account reference already exists")
	ErrDuplicateToken     = errors.New("verification token already exists")
)

type Account struct {
	Reference string
	Type      AccountType
	Verified  bool
}

type Token struct {
	Reference  string
	AccountRef string
	ExpiresAt  time.Time
	ConsumedAt *time.Time

	hash [sha256.Size]byte
}

type Event struct {
	AccountRef string
	TokenRef   string
	Outcome    Outcome
	OccurredAt time.Time
}

type Clock func() time.Time

type Service struct {
	mu       sync.Mutex
	attempts sync.Mutex

	clock    Clock
	accounts map[string]*Account
	tokens   map[[sha256.Size]byte]*Token
	active   map[[sha256.Size]byte]int
	events   []Event
}

func NewService(clock Clock) *Service {
	if clock == nil {
		clock = time.Now
	}

	return &Service{
		clock:    clock,
		accounts: map[string]*Account{},
		tokens:   map[[sha256.Size]byte]*Token{},
		active:   map[[sha256.Size]byte]int{},
	}
}

func (s *Service) Issue(account Account, tokenReference, submittedToken string, expiresAt time.Time) error {
	if account.Type != AccountTypeClient && account.Type != AccountTypeProvider {
		return ErrInvalidAccountType
	}
	if account.Reference == "" || tokenReference == "" || !validToken(submittedToken) {
		return ErrInvalidToken
	}

	hash := sha256.Sum256([]byte(submittedToken))

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.accounts[account.Reference]; ok {
		return ErrDuplicateAccount
	}
	if _, ok := s.tokens[hash]; ok {
		return ErrDuplicateToken
	}

	account.Verified = false
	s.accounts[account.Reference] = &account
	s.tokens[hash] = &Token{
		Reference:  tokenReference,
		AccountRef: account.Reference,
		ExpiresAt:  utcMilliseconds(expiresAt),
		hash:       hash,
	}
	return nil
}

func (s *Service) Verify(submittedToken string) Outcome {
	now := utcMilliseconds(s.clock())
	if !validToken(submittedToken) {
		s.record(Event{Outcome: OutcomeInvalid, OccurredAt: now})
		return OutcomeInvalid
	}

	hash := sha256.Sum256([]byte(submittedToken))
	concurrent := s.beginAttempt(hash)
	defer s.endAttempt(hash)

	s.mu.Lock()
	defer s.mu.Unlock()

	token, ok := s.tokens[hash]
	if !ok {
		s.appendEvent(Event{Outcome: OutcomeInvalid, OccurredAt: now})
		return OutcomeInvalid
	}

	event := Event{
		AccountRef: token.AccountRef,
		TokenRef:   token.Reference,
		OccurredAt: now,
	}

	if token.ConsumedAt != nil {
		if concurrent {
			event.Outcome = OutcomeConcurrentLoss
		} else {
			event.Outcome = OutcomeReplay
		}
		s.appendEvent(event)
		return event.Outcome
	}

	if !now.Before(token.ExpiresAt) {
		event.Outcome = OutcomeExpired
		s.appendEvent(event)
		return OutcomeExpired
	}

	account, ok := s.accounts[token.AccountRef]
	if !ok || (account.Type != AccountTypeClient && account.Type != AccountTypeProvider) {
		event.Outcome = OutcomeInvalid
		s.appendEvent(event)
		return OutcomeInvalid
	}

	consumedAt := now
	token.ConsumedAt = &consumedAt
	account.Verified = true
	event.Outcome = OutcomeSuccess
	s.appendEvent(event)
	return OutcomeSuccess
}

func (s *Service) Account(reference string) (Account, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	account, ok := s.accounts[reference]
	if !ok {
		return Account{}, false
	}
	return *account, true
}

func (s *Service) Token(reference string) (Token, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, token := range s.tokens {
		if token.Reference == reference {
			copy := *token
			copy.hash = [sha256.Size]byte{}
			return copy, true
		}
	}
	return Token{}, false
}

func (s *Service) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	events := make([]Event, len(s.events))
	copy(events, s.events)
	return events
}

func (s *Service) beginAttempt(hash [sha256.Size]byte) bool {
	s.attempts.Lock()
	defer s.attempts.Unlock()

	s.active[hash]++
	return s.active[hash] > 1
}

func (s *Service) endAttempt(hash [sha256.Size]byte) {
	s.attempts.Lock()
	defer s.attempts.Unlock()

	s.active[hash]--
	if s.active[hash] == 0 {
		delete(s.active, hash)
	}
}

func (s *Service) record(event Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendEvent(event)
}

func (s *Service) appendEvent(event Event) {
	s.events = append(s.events, event)
}

func validToken(token string) bool {
	if token == "" || len(token) > 1024 || strings.TrimSpace(token) != token {
		return false
	}
	for _, r := range token {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func utcMilliseconds(value time.Time) time.Time {
	return value.UTC().Truncate(time.Millisecond)
}
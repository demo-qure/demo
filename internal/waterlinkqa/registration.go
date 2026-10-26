package waterlinkqa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AccountType string

const (
	AccountTypeClient   AccountType = "CLIENT"
	AccountTypeProvider AccountType = "PROVIDER"
	AccountTypeOperator AccountType = "OPERATOR"
)

type ClientType string

const (
	ClientTypeResidential ClientType = "RESIDENTIAL"
	ClientTypeCommercial  ClientType = "COMMERCIAL"
)

type ProviderStatus string

const (
	ProviderStatusPending ProviderStatus = "PENDING"
)

const TestDataPurpose = "WaterLink QA synthetic identity testing only; production personal data is prohibited."

var (
	ErrDuplicateEmail = errors.New("email is already registered")
	ErrInvalidRequest = errors.New("invalid registration request")
)

type Account struct {
	ID               string         `json:"id"`
	Email            string         `json:"email"`
	PasswordHash     string         `json:"passwordHash"`
	AccountType      AccountType    `json:"accountType"`
	ClientType       ClientType     `json:"clientType,omitempty"`
	ProviderStatus   ProviderStatus `json:"providerStatus,omitempty"`
	EmailVerified    bool           `json:"emailVerified"`
	TestDataPurpose  string         `json:"testDataPurpose"`
	CreatedAt        time.Time      `json:"createdAt"`
}

type RegistrationRequest struct {
	Email       string      `json:"email"`
	Password    string      `json:"password"`
	AccountType AccountType `json:"accountType"`
	ClientType  ClientType  `json:"clientType,omitempty"`
}

type RegistrationResponse struct {
	ID              string         `json:"id"`
	Email           string         `json:"email"`
	AccountType     AccountType    `json:"accountType"`
	ClientType      ClientType     `json:"clientType,omitempty"`
	ProviderStatus  ProviderStatus `json:"providerStatus,omitempty"`
	EmailVerified   bool           `json:"emailVerified"`
	TestDataPurpose string         `json:"testDataPurpose"`
}

type AccountStore interface {
	CreateAccount(ctx context.Context, account Account) error
}

type SecurityEvent struct {
	Type        string    `json:"type"`
	OccurredAt  time.Time `json:"occurredAt"`
	RetainUntil time.Time `json:"retainUntil"`
	RemoteAddr  string    `json:"remoteAddr,omitempty"`
	Detail      string    `json:"detail"`
}

type SecurityEventSink interface {
	RecordSecurityEvent(ctx context.Context, event SecurityEvent)
}

type PasswordHasher interface {
	Hash(password string) (string, error)
}

type BcryptPasswordHasher struct {
	Cost int
}

func (h BcryptPasswordHasher) Hash(password string) (string, error) {
	cost := h.Cost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	return string(hash), nil
}

type RegistrationService struct {
	store  AccountStore
	hasher PasswordHasher
	now    func() time.Time
}

func NewRegistrationService(store AccountStore) *RegistrationService {
	return &RegistrationService{
		store:  store,
		hasher: BcryptPasswordHasher{},
		now:    time.Now,
	}
}

func (s *RegistrationService) Register(ctx context.Context, request RegistrationRequest) (*Account, error) {
	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	if err := validateRegistration(request); err != nil {
		return nil, err
	}

	passwordHash, err := s.hasher.Hash(request.Password)
	if err != nil {
		return nil, err
	}

	account := Account{
		ID:              uuid.NewString(),
		Email:           request.Email,
		PasswordHash:    passwordHash,
		AccountType:     request.AccountType,
		ClientType:      request.ClientType,
		EmailVerified:   false,
		TestDataPurpose: TestDataPurpose,
		CreatedAt:       s.now().UTC(),
	}
	if account.AccountType == AccountTypeProvider {
		account.ProviderStatus = ProviderStatusPending
		account.ClientType = ""
	}

	if err := s.store.CreateAccount(ctx, account); err != nil {
		return nil, err
	}
	return &account, nil
}

func validateRegistration(request RegistrationRequest) error {
	if request.Email == "" || request.Password == "" || request.AccountType == "" {
		return fmt.Errorf("%w: email, password, and accountType are required", ErrInvalidRequest)
	}
	if len(request.Password) < 12 {
		return fmt.Errorf("%w: password must contain at least 12 characters", ErrInvalidRequest)
	}

	address, err := mail.ParseAddress(request.Email)
	if err != nil || address.Address != request.Email {
		return fmt.Errorf("%w: email is invalid", ErrInvalidRequest)
	}
	parts := strings.Split(request.Email, "@")
	if len(parts) != 2 || !isSyntheticDomain(parts[1]) {
		return fmt.Errorf("%w: email must use a synthetic .test, .example, or .invalid domain", ErrInvalidRequest)
	}

	switch request.AccountType {
	case AccountTypeClient:
		if request.ClientType != ClientTypeResidential && request.ClientType != ClientTypeCommercial {
			return fmt.Errorf("%w: CLIENT requires RESIDENTIAL or COMMERCIAL clientType", ErrInvalidRequest)
		}
	case AccountTypeProvider:
		if request.ClientType != "" {
			return fmt.Errorf("%w: clientType is permitted only for CLIENT", ErrInvalidRequest)
		}
	default:
		return fmt.Errorf("%w: public registration permits only CLIENT or PROVIDER", ErrInvalidRequest)
	}

	return nil
}

func isSyntheticDomain(domain string) bool {
	domain = strings.ToLower(domain)
	return domain == "test" ||
		domain == "example" ||
		domain == "invalid" ||
		strings.HasSuffix(domain, ".test") ||
		strings.HasSuffix(domain, ".example") ||
		strings.HasSuffix(domain, ".invalid")
}

func NewRegistrationHandler(service *RegistrationService, events SecurityEventSink) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		var request RegistrationRequest
		if err := decoder.Decode(&request); err != nil {
			writeRegistrationError(w, http.StatusBadRequest, "invalid request")
			return
		}
		if decoder.Decode(&struct{}{}) == nil {
			writeRegistrationError(w, http.StatusBadRequest, "request must contain one JSON object")
			return
		}

		if request.AccountType == AccountTypeOperator && events != nil {
			now := time.Now().UTC()
			events.RecordSecurityEvent(r.Context(), SecurityEvent{
				Type:        "registration.role_assignment_denied",
				OccurredAt:  now,
				RetainUntil: now.AddDate(1, 0, 0),
				RemoteAddr:  r.RemoteAddr,
				Detail:      "public OPERATOR assignment denied",
			})
		}

		account, err := service.Register(r.Context(), request)
		if err != nil {
			switch {
			case errors.Is(err, ErrDuplicateEmail):
				writeRegistrationError(w, http.StatusConflict, "email is already registered")
			case errors.Is(err, ErrInvalidRequest):
				writeRegistrationError(w, http.StatusBadRequest, err.Error())
			default:
				writeRegistrationError(w, http.StatusInternalServerError, "internal error")
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(RegistrationResponse{
			ID:              account.ID,
			Email:           account.Email,
			AccountType:     account.AccountType,
			ClientType:      account.ClientType,
			ProviderStatus:  account.ProviderStatus,
			EmailVerified:   account.EmailVerified,
			TestDataPurpose: account.TestDataPurpose,
		})
	})
}

func writeRegistrationError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{
		Error: message,
	})
}
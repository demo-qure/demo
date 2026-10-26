package waterlinkqa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountUnverified  = errors.New("account is not verified")
	ErrInvalidSession     = errors.New("invalid session")
	ErrSessionExpired     = errors.New("session expired")
	ErrInvalidTimeout     = errors.New("session inactivity timeout must be positive")
)

type CredentialVerifier func(ctx context.Context, email, password string) (accountID string, verified bool, err error)

type SecurityEventRecorder func(ctx context.Context, event SecurityEvent)

type AuthenticationService struct {
	mu                sync.Mutex
	verifyCredentials CredentialVerifier
	recordEvent       SecurityEventRecorder
	inactivityTimeout time.Duration
	now               func() time.Time
	sessions          map[[sha256.Size]byte]authenticationSession
}

type authenticationSession struct {
	accountID  string
	lastActive time.Time
}

func NewAuthenticationService(
	verifyCredentials CredentialVerifier,
	recordEvent SecurityEventRecorder,
	inactivityTimeout time.Duration,
) (*AuthenticationService, error) {
	if verifyCredentials == nil {
		return nil, errors.New("credential verifier is required")
	}
	if inactivityTimeout <= 0 {
		return nil, ErrInvalidTimeout
	}
	if recordEvent == nil {
		recordEvent = func(context.Context, SecurityEvent) {}
	}

	return &AuthenticationService{
		verifyCredentials: verifyCredentials,
		recordEvent:       recordEvent,
		inactivityTimeout: inactivityTimeout,
		now:               time.Now,
		sessions:          make(map[[sha256.Size]byte]authenticationSession),
	}, nil
}

func (s *AuthenticationService) Login(ctx context.Context, email, password string) (string, error) {
	accountID, verified, err := s.verifyCredentials(ctx, email, password)
	if err != nil || accountID == "" {
		s.recordEvent(ctx, SecurityEvent{
			Type:      "AUTHENTICATION_DENIED",
			OccurredAt: s.now().UTC(),
		})
		return "", ErrInvalidCredentials
	}
	if !verified {
		s.recordEvent(ctx, SecurityEvent{
			Type:      "UNVERIFIED_AUTHENTICATION_DENIED",
			AccountID: accountID,
			OccurredAt: s.now().UTC(),
		})
		return "", ErrAccountUnverified
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", errors.New("generating session token")
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	digest := sha256.Sum256([]byte(token))

	s.mu.Lock()
	s.sessions[digest] = authenticationSession{
		accountID:  accountID,
		lastActive: s.now().UTC(),
	}
	s.mu.Unlock()

	return token, nil
}

func (s *AuthenticationService) Authenticate(ctx context.Context, token string) (string, error) {
	if token == "" {
		s.recordEvent(ctx, SecurityEvent{
			Type:      "SESSION_DENIED",
			OccurredAt: s.now().UTC(),
		})
		return "", ErrInvalidSession
	}

	digest := sha256.Sum256([]byte(token))
	now := s.now().UTC()

	s.mu.Lock()
	session, ok := s.sessions[digest]
	if !ok {
		s.mu.Unlock()
		s.recordEvent(ctx, SecurityEvent{
			Type:      "SESSION_DENIED",
			OccurredAt: now,
		})
		return "", ErrInvalidSession
	}
	if !now.Before(session.lastActive.Add(s.inactivityTimeout)) {
		delete(s.sessions, digest)
		s.mu.Unlock()
		s.recordEvent(ctx, SecurityEvent{
			Type:      "SESSION_EXPIRED",
			AccountID: session.accountID,
			OccurredAt: now,
		})
		return "", ErrSessionExpired
	}
	session.lastActive = now
	s.sessions[digest] = session
	s.mu.Unlock()

	return session.accountID, nil
}

func (s *AuthenticationService) Logout(token string) {
	if token == "" {
		return
	}

	digest := sha256.Sum256([]byte(token))
	s.mu.Lock()
	delete(s.sessions, digest)
	s.mu.Unlock()
}
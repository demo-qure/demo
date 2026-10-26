package waterlinkqa

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAuthenticationServiceLoginRequiresValidVerifiedAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		accountID  string
		verified   bool
		verifyErr  error
		wantErr    error
		wantEvents int
	}{
		{
			name:      "valid verified account",
			accountID: "account-1",
			verified:  true,
		},
		{
			name:       "invalid credentials",
			verifyErr:  errors.New("password mismatch"),
			wantErr:    ErrInvalidCredentials,
			wantEvents: 1,
		},
		{
			name:       "unverified account",
			accountID:  "account-1",
			wantErr:    ErrAccountUnverified,
			wantEvents: 1,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var events []SecurityEvent
			service, err := NewAuthenticationService(
				func(context.Context, string, string) (string, bool, error) {
					return test.accountID, test.verified, test.verifyErr
				},
				func(_ context.Context, event SecurityEvent) {
					events = append(events, event)
				},
				time.Minute,
			)
			if err != nil {
				t.Fatalf("NewAuthenticationService() error = %v", err)
			}

			token, err := service.Login(context.Background(), "synthetic@example.test", "password")
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Login() error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && token == "" {
				t.Fatal("Login() returned an empty token")
			}
			if test.wantErr != nil && token != "" {
				t.Fatal("Login() created a session after denial")
			}
			if len(events) != test.wantEvents {
				t.Fatalf("recorded %d events, want %d", len(events), test.wantEvents)
			}
		})
	}
}

func TestAuthenticationServiceLogoutInvalidatesSession(t *testing.T) {
	t.Parallel()

	service := newVerifiedAuthenticationService(t, time.Minute)
	token, err := service.Login(context.Background(), "synthetic@example.test", "password")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if accountID, err := service.Authenticate(context.Background(), token); err != nil || accountID != "account-1" {
		t.Fatalf("Authenticate() = %q, %v", accountID, err)
	}

	service.Logout(token)

	if _, err := service.Authenticate(context.Background(), token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("Authenticate() after logout error = %v, want %v", err, ErrInvalidSession)
	}
}

func TestAuthenticationServiceRejectsSessionAtInactivityBoundary(t *testing.T) {
	t.Parallel()

	timeout := time.Minute
	service := newVerifiedAuthenticationService(t, timeout)
	now := time.Date(2026, time.October, 20, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time {
		return now
	}

	token, err := service.Login(context.Background(), "synthetic@example.test", "password")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	now = now.Add(timeout)
	if _, err := service.Authenticate(context.Background(), token); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Authenticate() at expiry error = %v, want %v", err, ErrSessionExpired)
	}
	if _, err := service.Authenticate(context.Background(), token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("Authenticate() after expiry error = %v, want %v", err, ErrInvalidSession)
	}
}

func TestAuthenticationServiceRefreshesActivity(t *testing.T) {
	t.Parallel()

	timeout := time.Minute
	service := newVerifiedAuthenticationService(t, timeout)
	now := time.Date(2026, time.October, 20, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time {
		return now
	}

	token, err := service.Login(context.Background(), "synthetic@example.test", "password")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	now = now.Add(30 * time.Second)
	if _, err := service.Authenticate(context.Background(), token); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	now = now.Add(45 * time.Second)
	if _, err := service.Authenticate(context.Background(), token); err != nil {
		t.Fatalf("Authenticate() after refreshed activity error = %v", err)
	}
}

func TestAuthenticationServiceAllowsOnlyOneSuccessfulUseAfterConcurrentLogout(t *testing.T) {
	t.Parallel()

	service := newVerifiedAuthenticationService(t, time.Minute)
	token, err := service.Login(context.Background(), "synthetic@example.test", "password")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})
	results := make(chan error, 1)

	go func() {
		defer wg.Done()
		<-start
		service.Logout(token)
	}()
	go func() {
		defer wg.Done()
		<-start
		_, err := service.Authenticate(context.Background(), token)
		results <- err
	}()

	close(start)
	wg.Wait()
	close(results)

	if err := <-results; err != nil && !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("concurrent Authenticate() error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("Authenticate() after concurrent logout error = %v, want %v", err, ErrInvalidSession)
	}
}

func newVerifiedAuthenticationService(t *testing.T, timeout time.Duration) *AuthenticationService {
	t.Helper()

	service, err := NewAuthenticationService(
		func(context.Context, string, string) (string, bool, error) {
			return "account-1", true, nil
		},
		nil,
		timeout,
	)
	if err != nil {
		t.Fatalf("NewAuthenticationService() error = %v", err)
	}
	return service
}
package waterlinkqa

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type recordingEventSink struct {
	events []SecurityEvent
}

func (s *recordingEventSink) RecordSecurityEvent(_ context.Context, event SecurityEvent) {
	s.events = append(s.events, event)
}

func TestRegistrationHandlerCreatesSyntheticAccounts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		request                string
		expectedAccountType    AccountType
		expectedClientType     ClientType
		expectedProviderStatus ProviderStatus
	}{
		{
			name:                "residential client",
			request:             `{"email":"client@waterlink.test","password":"synthetic-passphrase","accountType":"CLIENT","clientType":"RESIDENTIAL"}`,
			expectedAccountType: AccountTypeClient,
			expectedClientType:  ClientTypeResidential,
		},
		{
			name:                   "pending provider",
			request:                `{"email":"provider@waterlink.test","password":"synthetic-passphrase","accountType":"PROVIDER"}`,
			expectedAccountType:    AccountTypeProvider,
			expectedProviderStatus: ProviderStatusPending,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "accounts.json")
			store, err := NewFileAccountStore(path)
			require.NoError(t, err)
			handler := NewRegistrationHandler(NewRegistrationService(store), nil)

			request := httptest.NewRequest(http.MethodPost, "/waterlink/registrations", bytes.NewBufferString(test.request))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			require.Equal(t, http.StatusCreated, response.Code)
			var registration RegistrationResponse
			require.NoError(t, json.NewDecoder(response.Body).Decode(&registration))
			require.NotEmpty(t, registration.ID)
			require.Equal(t, test.expectedAccountType, registration.AccountType)
			require.Equal(t, test.expectedClientType, registration.ClientType)
			require.Equal(t, test.expectedProviderStatus, registration.ProviderStatus)
			require.False(t, registration.EmailVerified)
			require.Equal(t, TestDataPurpose, registration.TestDataPurpose)

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			var accounts []Account
			require.NoError(t, json.Unmarshal(data, &accounts))
			require.Len(t, accounts, 1)
			require.NotEqual(t, "synthetic-passphrase", accounts[0].PasswordHash)
			require.NoError(t, bcrypt.CompareHashAndPassword([]byte(accounts[0].PasswordHash), []byte("synthetic-passphrase")))
		})
	}
}

func TestRegistrationHandlerRejectsInvalidRegistrationsWithoutCreatingAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		request    string
		wantStatus int
		wantEvent  bool
	}{
		{
			name:       "missing required password",
			request:    `{"email":"client@waterlink.test","accountType":"CLIENT","clientType":"COMMERCIAL"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "operator role escalation",
			request:    `{"email":"operator@waterlink.test","password":"synthetic-passphrase","accountType":"OPERATOR"}`,
			wantStatus: http.StatusBadRequest,
			wantEvent:  true,
		},
		{
			name:       "production-like email",
			request:    `{"email":"person@example.com","password":"synthetic-passphrase","accountType":"PROVIDER"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "client missing classification",
			request:    `{"email":"client@waterlink.test","password":"synthetic-passphrase","accountType":"CLIENT"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unknown collected field",
			request:    `{"email":"client@waterlink.test","password":"synthetic-passphrase","accountType":"CLIENT","clientType":"RESIDENTIAL","name":"not collected"}`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "accounts.json")
			store, err := NewFileAccountStore(path)
			require.NoError(t, err)
			events := &recordingEventSink{}
			handler := NewRegistrationHandler(NewRegistrationService(store), events)

			request := httptest.NewRequest(http.MethodPost, "/waterlink/registrations", bytes.NewBufferString(test.request))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			require.Equal(t, test.wantStatus, response.Code)
			_, err = os.Stat(path)
			require.ErrorIs(t, err, os.ErrNotExist)
			if test.wantEvent {
				require.Len(t, events.events, 1)
				require.Equal(t, "registration.role_assignment_denied", events.events[0].Type)
				require.False(t, events.events[0].RetainUntil.Before(events.events[0].OccurredAt.AddDate(1, 0, 0)))
			} else {
				require.Empty(t, events.events)
			}
		})
	}
}

func TestRegistrationHandlerRejectsDuplicateEmail(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := NewFileAccountStore(path)
	require.NoError(t, err)
	handler := NewRegistrationHandler(NewRegistrationService(store), nil)

	body := `{"email":"provider@waterlink.test","password":"synthetic-passphrase","accountType":"PROVIDER"}`
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/waterlink/registrations", bytes.NewBufferString(body)))
	require.Equal(t, http.StatusCreated, first.Code)

	duplicate := httptest.NewRecorder()
	handler.ServeHTTP(duplicate, httptest.NewRequest(
		http.MethodPost,
		"/waterlink/registrations",
		bytes.NewBufferString(`{"email":"PROVIDER@WATERLINK.TEST","password":"another-passphrase","accountType":"PROVIDER"}`),
	))
	require.Equal(t, http.StatusConflict, duplicate.Code)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var accounts []Account
	require.NoError(t, json.Unmarshal(data, &accounts))
	require.Len(t, accounts, 1)
}
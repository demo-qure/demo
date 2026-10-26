package waterlinkqa

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestAuthorizeProviderOrderAcceptance(t *testing.T) {
	tests := []struct {
		name   string
		role   string
		status string
		want   error
	}{
		{name: "approved provider", role: "PROVIDER", status: "APPROVED"},
		{name: "pending provider", role: "PROVIDER", status: "PENDING", want: ErrProviderNotApproved},
		{name: "rejected provider", role: "PROVIDER", status: "REJECTED", want: ErrProviderNotApproved},
		{name: "approved client", role: "CLIENT", status: "APPROVED", want: ErrProviderNotApproved},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account := newAuthorizationTestAccount(t, "account-1", test.role, test.status)
			err := AuthorizeProviderOrderAcceptance(account)
			if !errors.Is(err, test.want) {
				t.Fatalf("AuthorizeProviderOrderAcceptance() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRequireProviderOrderAcceptanceUsesResolvedPersistedState(t *testing.T) {
	account := newAuthorizationTestAccount(t, "provider-1", "PROVIDER", "PENDING")
	var events []string
	guard := NewAuthorizationGuard(
		func(context.Context, *http.Request) (*Account, error) {
			return account, nil
		},
		func(_ context.Context, event string, _ map[string]string) {
			events = append(events, event)
		},
	)

	called := false
	handler := guard.RequireProviderOrderAcceptance(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/provider/capability", nil))

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if called {
		t.Fatal("protected handler was called for pending provider")
	}
	if len(events) != 1 || events[0] != authorizationEventProviderStateDenied {
		t.Fatalf("events = %v, want provider-state denial", events)
	}
}

func TestAuthorizeRoleUpdateDeniesSelfEscalationWithoutMutation(t *testing.T) {
	account := newAuthorizationTestAccount(t, "client-1", "CLIENT", "")
	guard := NewAuthorizationGuard(
		func(context.Context, *http.Request) (*Account, error) {
			return account, nil
		},
		nil,
	)

	_, err := guard.AuthorizeRoleUpdate(
		httptest.NewRequest(http.MethodPatch, "/accounts/client-1", nil),
		account,
		"OPERATOR",
	)
	if !errors.Is(err, ErrRoleMutationDenied) {
		t.Fatalf("AuthorizeRoleUpdate() error = %v, want %v", err, ErrRoleMutationDenied)
	}
	if got := accountRole(account); got != "CLIENT" {
		t.Fatalf("role changed to %q, want CLIENT", got)
	}
}

func TestAuthorizeAccountAccessDeniesCrossAccountAttemptAndRecordsEvent(t *testing.T) {
	account := newAuthorizationTestAccount(t, "client-1", "CLIENT", "")
	var event string
	var fields map[string]string
	guard := NewAuthorizationGuard(
		func(context.Context, *http.Request) (*Account, error) {
			return account, nil
		},
		func(_ context.Context, gotEvent string, gotFields map[string]string) {
			event = gotEvent
			fields = gotFields
		},
	)

	_, err := guard.AuthorizeAccountAccess(
		httptest.NewRequest(http.MethodGet, "/accounts/client-2", nil),
		"client-2",
	)
	if !errors.Is(err, ErrCrossAccountAccess) {
		t.Fatalf("AuthorizeAccountAccess() error = %v, want %v", err, ErrCrossAccountAccess)
	}
	if event != authorizationEventCrossAccountDenied {
		t.Fatalf("event = %q, want %q", event, authorizationEventCrossAccountDenied)
	}
	if fields["actor_account_id"] != "client-1" || fields["target_account_id"] != "client-2" {
		t.Fatalf("unexpected event fields: %v", fields)
	}
}

func newAuthorizationTestAccount(t *testing.T, id, role, status string) *Account {
	t.Helper()

	account := &Account{}
	setAuthorizationTestField(t, account, "ID", id)
	setAuthorizationTestField(t, account, "Role", role)
	if status != "" {
		setAuthorizationTestField(t, account, "ProviderStatus", status)
	}
	return account
}

func setAuthorizationTestField(t *testing.T, account *Account, name, value string) {
	t.Helper()

	field := reflect.ValueOf(account).Elem().FieldByName(name)
	if !field.IsValid() {
		t.Fatalf("Account.%s is required by authorization", name)
	}

	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Pointer:
		if field.Type().Elem().Kind() != reflect.String {
			t.Fatalf("Account.%s has unsupported type %s", name, field.Type())
		}
		item := reflect.New(field.Type().Elem())
		item.Elem().SetString(value)
		field.Set(item)
	default:
		t.Fatalf("Account.%s has unsupported type %s", name, field.Type())
	}
}
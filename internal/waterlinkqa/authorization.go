package waterlinkqa

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
)

var (
	ErrAuthenticationRequired = errors.New("authentication required")
	ErrRoleMutationDenied      = errors.New("role mutation denied")
	ErrCrossAccountAccess      = errors.New("cross-account access denied")
	ErrProviderNotApproved     = errors.New("provider is not approved")
)

const (
	authorizationEventRoleMutationDenied  = "role_mutation_denied"
	authorizationEventCrossAccountDenied  = "cross_account_access_denied"
	authorizationEventProviderStateDenied = "provider_capability_denied"
)

// SessionAccountResolver resolves the authenticated identity from a server-side
// session and reloads its current persisted Account state.
type SessionAccountResolver func(context.Context, *http.Request) (*Account, error)

// AuthorizationEventRecorder forwards denied authorization decisions to the
// application's security-event log and monitoring pipeline.
type AuthorizationEventRecorder func(context.Context, string, map[string]string)

type AuthorizationGuard struct {
	resolve SessionAccountResolver
	record  AuthorizationEventRecorder
}

func NewAuthorizationGuard(resolve SessionAccountResolver, record AuthorizationEventRecorder) *AuthorizationGuard {
	return &AuthorizationGuard{
		resolve: resolve,
		record:  record,
	}
}

func (g *AuthorizationGuard) RequireProviderOrderAcceptance(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, err := g.authenticatedAccount(r)
		if err != nil {
			http.Error(w, ErrAuthenticationRequired.Error(), http.StatusUnauthorized)
			return
		}

		if err := AuthorizeProviderOrderAcceptance(account); err != nil {
			g.denied(r.Context(), authorizationEventProviderStateDenied, account, map[string]string{
				"capability": "provider_order_acceptance",
			})
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (g *AuthorizationGuard) AuthorizeAccountAccess(r *http.Request, targetAccountID string) (*Account, error) {
	account, err := g.authenticatedAccount(r)
	if err != nil {
		return nil, ErrAuthenticationRequired
	}

	if accountID(account) != targetAccountID {
		g.denied(r.Context(), authorizationEventCrossAccountDenied, account, map[string]string{
			"target_account_id": targetAccountID,
		})
		return nil, ErrCrossAccountAccess
	}

	return account, nil
}

func (g *AuthorizationGuard) AuthorizeRoleUpdate(r *http.Request, target *Account, requestedRole string) (*Account, error) {
	account, err := g.authenticatedAccount(r)
	if err != nil {
		return nil, ErrAuthenticationRequired
	}

	currentRole := accountRole(target)
	if accountID(account) == accountID(target) || requestedRole != currentRole {
		g.denied(r.Context(), authorizationEventRoleMutationDenied, account, map[string]string{
			"target_account_id": accountID(target),
			"current_role":      currentRole,
			"requested_role":    requestedRole,
		})
		return nil, ErrRoleMutationDenied
	}

	return account, nil
}

func (g *AuthorizationGuard) authenticatedAccount(r *http.Request) (*Account, error) {
	if g == nil || g.resolve == nil {
		return nil, ErrAuthenticationRequired
	}

	account, err := g.resolve(r.Context(), r)
	if err != nil || account == nil || accountID(account) == "" {
		return nil, ErrAuthenticationRequired
	}

	return account, nil
}

func (g *AuthorizationGuard) denied(ctx context.Context, event string, account *Account, fields map[string]string) {
	if g == nil || g.record == nil {
		return
	}

	if fields == nil {
		fields = map[string]string{}
	}
	fields["actor_account_id"] = accountID(account)
	fields["actor_role"] = accountRole(account)
	g.record(ctx, event, fields)
}

// AuthorizeProviderOrderAcceptance evaluates only eligibility for the future
// Release 2 capability. It does not implement an order workflow.
func AuthorizeProviderOrderAcceptance(account *Account) error {
	if account == nil ||
		accountRole(account) != "PROVIDER" ||
		accountProviderStatus(account) != "APPROVED" {
		return ErrProviderNotApproved
	}

	return nil
}

func accountID(account *Account) string {
	return accountStringField(account, "ID")
}

func accountRole(account *Account) string {
	return strings.ToUpper(accountStringField(account, "Role"))
}

func accountProviderStatus(account *Account) string {
	return strings.ToUpper(accountStringField(account, "ProviderStatus"))
}

func accountStringField(account *Account, name string) string {
	if account == nil {
		return ""
	}

	value := reflect.ValueOf(account)
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return ""
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return ""
	}

	field := value.FieldByName(name)
	if !field.IsValid() {
		return ""
	}

	switch field.Kind() {
	case reflect.String:
		return field.String()
	case reflect.Pointer:
		if !field.IsNil() && field.Elem().Kind() == reflect.String {
			return field.Elem().String()
		}
	}

	return ""
}
package waterlinkqa

import (
	"errors"
	"fmt"
	"log/slog"
)

var ErrAccountAccessDenied = errors.New("account access denied")

type SessionPrincipal struct {
	AccountID   string
	AccountType string
}

type AccountProfile struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	AccountType string `json:"accountType"`
}

type ProviderOnboardingRecord struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	ProviderStatus string `json:"providerStatus"`
}

type AccountAccessDenial struct {
	PrincipalID        string
	PrincipalType      string
	RequestedAccountID string
	Operation          string
	Reason             string
}

type AccountAccessDenialRecorder func(AccountAccessDenial)

type AccountAccessPolicy struct {
	recordDenial AccountAccessDenialRecorder
}

func NewAccountAccessPolicy(recordDenial AccountAccessDenialRecorder) *AccountAccessPolicy {
	if recordDenial == nil {
		recordDenial = func(denial AccountAccessDenial) {
			slog.Warn(
				"waterlink account access denied",
				"principal_id", denial.PrincipalID,
				"principal_type", denial.PrincipalType,
				"requested_account_id", denial.RequestedAccountID,
				"operation", denial.Operation,
				"reason", denial.Reason,
			)
		}
	}

	return &AccountAccessPolicy{recordDenial: recordDenial}
}

func (p *AccountAccessPolicy) Profile(principal SessionPrincipal, account Account) (AccountProfile, error) {
	accountID := fmt.Sprint(account.ID)
	if principal.AccountID == "" || principal.AccountID != accountID {
		p.deny(principal, accountID, "read_profile", "cross_account")
		return AccountProfile{}, ErrAccountAccessDenied
	}

	return AccountProfile{
		ID:          accountID,
		Email:       account.Email,
		AccountType: fmt.Sprint(account.AccountType),
	}, nil
}

func (p *AccountAccessPolicy) ProviderOnboarding(
	principal SessionPrincipal,
	account Account,
) (ProviderOnboardingRecord, error) {
	accountID := fmt.Sprint(account.ID)
	if principal.AccountID == "" || principal.AccountType != "OPERATOR" {
		p.deny(principal, accountID, "read_provider_onboarding", "operator_required")
		return ProviderOnboardingRecord{}, ErrAccountAccessDenied
	}
	if fmt.Sprint(account.AccountType) != "PROVIDER" {
		p.deny(principal, accountID, "read_provider_onboarding", "provider_required")
		return ProviderOnboardingRecord{}, ErrAccountAccessDenied
	}

	return ProviderOnboardingRecord{
		ID:             accountID,
		Email:          account.Email,
		ProviderStatus: fmt.Sprint(account.ProviderStatus),
	}, nil
}

func (p *AccountAccessPolicy) deny(
	principal SessionPrincipal,
	requestedAccountID string,
	operation string,
	reason string,
) {
	p.recordDenial(AccountAccessDenial{
		PrincipalID:        principal.AccountID,
		PrincipalType:      principal.AccountType,
		RequestedAccountID: requestedAccountID,
		Operation:          operation,
		Reason:             reason,
	})
}
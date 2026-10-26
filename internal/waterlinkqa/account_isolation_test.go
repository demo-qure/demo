package waterlinkqa

import (
	"errors"
	"reflect"
	"testing"
)

func TestAccountAccessPolicyProfileUsesAccountOwnership(t *testing.T) {
	first := Account{
		ID:          "client-1",
		Email:       "client-1@example.test",
		AccountType: "CLIENT",
	}
	second := Account{
		ID:          "client-2",
		Email:       "client-2@example.test",
		AccountType: "CLIENT",
	}

	var denials []AccountAccessDenial
	policy := NewAccountAccessPolicy(func(denial AccountAccessDenial) {
		denials = append(denials, denial)
	})

	profile, err := policy.Profile(SessionPrincipal{
		AccountID:   first.ID,
		AccountType: "CLIENT",
	}, first)
	if err != nil {
		t.Fatalf("read own profile: %v", err)
	}
	if profile.ID != first.ID || profile.Email != first.Email || profile.AccountType != "CLIENT" {
		t.Fatalf("unexpected profile: %#v", profile)
	}

	profile, err = policy.Profile(SessionPrincipal{
		AccountID:   first.ID,
		AccountType: "CLIENT",
	}, second)
	if !errors.Is(err, ErrAccountAccessDenied) {
		t.Fatalf("expected account access denial, got %v", err)
	}
	if !reflect.DeepEqual(profile, AccountProfile{}) {
		t.Fatalf("denied response disclosed profile fields: %#v", profile)
	}
	if len(denials) != 1 || denials[0].Reason != "cross_account" {
		t.Fatalf("expected one cross-account denial event, got %#v", denials)
	}
}

func TestAccountAccessPolicyProviderOnboardingIsOperatorOnlyAndMinimized(t *testing.T) {
	provider := Account{
		ID:             "provider-1",
		Email:          "provider-1@example.test",
		AccountType:    "PROVIDER",
		ProviderStatus: "PENDING",
	}

	var denials []AccountAccessDenial
	policy := NewAccountAccessPolicy(func(denial AccountAccessDenial) {
		denials = append(denials, denial)
	})

	record, err := policy.ProviderOnboarding(SessionPrincipal{
		AccountID:   "operator-1",
		AccountType: "OPERATOR",
	}, provider)
	if err != nil {
		t.Fatalf("operator read provider onboarding: %v", err)
	}
	if record.ID != provider.ID ||
		record.Email != provider.Email ||
		record.ProviderStatus != "PENDING" {
		t.Fatalf("unexpected onboarding record: %#v", record)
	}

	recordType := reflect.TypeOf(record)
	for _, prohibited := range []string{
		"Password",
		"PasswordHash",
		"VerificationToken",
		"VerificationTokenHash",
		"Role",
	} {
		if _, found := recordType.FieldByName(prohibited); found {
			t.Fatalf("onboarding record exposes prohibited field %q", prohibited)
		}
	}

	record, err = policy.ProviderOnboarding(SessionPrincipal{
		AccountID:   provider.ID,
		AccountType: "PROVIDER",
	}, provider)
	if !errors.Is(err, ErrAccountAccessDenied) {
		t.Fatalf("expected provider onboarding denial, got %v", err)
	}
	if !reflect.DeepEqual(record, ProviderOnboardingRecord{}) {
		t.Fatalf("denied response disclosed onboarding fields: %#v", record)
	}
	if len(denials) != 1 || denials[0].Reason != "operator_required" {
		t.Fatalf("expected one operator-required denial event, got %#v", denials)
	}
}

func TestAccountAccessPolicyOperatorCannotReadClientAsOnboarding(t *testing.T) {
	client := Account{
		ID:          "client-1",
		Email:       "client-1@example.test",
		AccountType: "CLIENT",
	}

	var denial AccountAccessDenial
	policy := NewAccountAccessPolicy(func(recorded AccountAccessDenial) {
		denial = recorded
	})

	record, err := policy.ProviderOnboarding(SessionPrincipal{
		AccountID:   "operator-1",
		AccountType: "OPERATOR",
	}, client)
	if !errors.Is(err, ErrAccountAccessDenied) {
		t.Fatalf("expected non-provider denial, got %v", err)
	}
	if !reflect.DeepEqual(record, ProviderOnboardingRecord{}) {
		t.Fatalf("denied response disclosed account fields: %#v", record)
	}
	if denial.Reason != "provider_required" {
		t.Fatalf("expected provider-required denial event, got %#v", denial)
	}
}
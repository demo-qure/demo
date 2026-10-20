package waterlinkqa

import (
	"errors"
	"testing"
	"time"
)

func TestDecideApprovesPendingProvider(t *testing.T) {
	now := time.Date(2026, time.October, 20, 9, 30, 0, 0, time.FixedZone("AST", 3*60*60))
	service := NewService(func() time.Time { return now })
	operator := Actor{ID: "synthetic-operator-1", Role: RoleOperator, Authenticated: true}
	provider := Provider{ID: "synthetic-provider-1", Status: ProviderPending}

	decision, err := service.Decide(operator, &provider, OutcomeApproved, "synthetic verification passed")
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}

	if provider.Status != ProviderApproved {
		t.Fatalf("provider status = %q, want %q", provider.Status, ProviderApproved)
	}
	if decision.ProviderID() != provider.ID {
		t.Errorf("provider ID = %q, want %q", decision.ProviderID(), provider.ID)
	}
	if decision.OperatorID() != operator.ID {
		t.Errorf("operator ID = %q, want %q", decision.OperatorID(), operator.ID)
	}
	if decision.Outcome() != OutcomeApproved {
		t.Errorf("outcome = %q, want %q", decision.Outcome(), OutcomeApproved)
	}
	if !decision.Timestamp().Equal(now) {
		t.Errorf("timestamp = %v, want %v", decision.Timestamp(), now)
	}
	if decision.Timestamp().Location() != time.UTC {
		t.Errorf("timestamp location = %v, want UTC", decision.Timestamp().Location())
	}
	if decision.Reason() != "synthetic verification passed" {
		t.Errorf("reason = %q, want supplied reason", decision.Reason())
	}

	decisions, err := service.Decisions(operator)
	if err != nil {
		t.Fatalf("Decisions() error = %v", err)
	}
	if len(decisions) != 1 {
		t.Fatalf("decision count = %d, want 1", len(decisions))
	}
	if decisions[0].ProviderID() != provider.ID {
		t.Errorf("recorded provider ID = %q, want %q", decisions[0].ProviderID(), provider.ID)
	}
}

func TestDecideRejectsPendingProviderWithoutReason(t *testing.T) {
	service := NewService(func() time.Time {
		return time.Date(2026, time.October, 20, 7, 0, 0, 0, time.UTC)
	})
	operator := Actor{ID: "synthetic-operator-1", Role: RoleOperator, Authenticated: true}
	provider := Provider{ID: "synthetic-provider-2", Status: ProviderPending}

	decision, err := service.Decide(operator, &provider, OutcomeRejected, "")
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}

	if provider.Status != ProviderRejected {
		t.Fatalf("provider status = %q, want %q", provider.Status, ProviderRejected)
	}
	if decision.Outcome() != OutcomeRejected {
		t.Errorf("outcome = %q, want %q", decision.Outcome(), OutcomeRejected)
	}
	if decision.Reason() != "" {
		t.Errorf("reason = %q, want empty", decision.Reason())
	}
}

func TestDecideDenialsLeaveProviderPending(t *testing.T) {
	operatorID := "synthetic-operator-1"

	tests := []struct {
		name    string
		actor   Actor
		outcome Outcome
		wantErr error
	}{
		{
			name:    "unauthenticated",
			actor:   Actor{ID: operatorID, Role: RoleOperator},
			outcome: OutcomeApproved,
			wantErr: ErrUnauthenticated,
		},
		{
			name:    "client",
			actor:   Actor{ID: "synthetic-client-1", Role: RoleClient, Authenticated: true},
			outcome: OutcomeApproved,
			wantErr: ErrForbidden,
		},
		{
			name:    "provider",
			actor:   Actor{ID: "synthetic-provider-2", Role: RoleProvider, Authenticated: true},
			outcome: OutcomeApproved,
			wantErr: ErrForbidden,
		},
		{
			name:    "self approval",
			actor:   Actor{ID: "synthetic-provider-1", Role: RoleOperator, Authenticated: true},
			outcome: OutcomeApproved,
			wantErr: ErrSelfApproval,
		},
		{
			name:    "invalid outcome",
			actor:   Actor{ID: operatorID, Role: RoleOperator, Authenticated: true},
			outcome: Outcome("ESCALATED"),
			wantErr: ErrInvalidOutcome,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewService(nil)
			provider := Provider{ID: "synthetic-provider-1", Status: ProviderPending}

			_, err := service.Decide(tt.actor, &provider, tt.outcome, "not persisted")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Decide() error = %v, want %v", err, tt.wantErr)
			}
			if provider.Status != ProviderPending {
				t.Errorf("provider status = %q, want unchanged %q", provider.Status, ProviderPending)
			}

			decisions, err := service.Decisions(Actor{
				ID:            operatorID,
				Role:          RoleOperator,
				Authenticated: true,
			})
			if err != nil {
				t.Fatalf("Decisions() error = %v", err)
			}
			if len(decisions) != 0 {
				t.Errorf("decision count = %d, want 0", len(decisions))
			}
		})
	}
}

func TestDecideRejectsNonPendingProviderWithoutStateChange(t *testing.T) {
	service := NewService(nil)
	operator := Actor{ID: "synthetic-operator-1", Role: RoleOperator, Authenticated: true}

	for _, status := range []ProviderStatus{ProviderApproved, ProviderRejected} {
		t.Run(string(status), func(t *testing.T) {
			provider := Provider{ID: "synthetic-provider-1", Status: status}

			_, err := service.Decide(operator, &provider, OutcomeRejected, "not persisted")
			if !errors.Is(err, ErrProviderNotPending) {
				t.Fatalf("Decide() error = %v, want %v", err, ErrProviderNotPending)
			}
			if provider.Status != status {
				t.Errorf("provider status = %q, want unchanged %q", provider.Status, status)
			}
		})
	}
}

func TestDecisionRecordsAndDenialEventsAreOperatorRestricted(t *testing.T) {
	service := NewService(nil)
	client := Actor{ID: "synthetic-client-1", Role: RoleClient, Authenticated: true}
	operator := Actor{ID: "synthetic-operator-1", Role: RoleOperator, Authenticated: true}

	if _, err := service.Decisions(client); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Decisions() error = %v, want %v", err, ErrForbidden)
	}
	if _, err := service.SecurityEvents(client); !errors.Is(err, ErrForbidden) {
		t.Fatalf("SecurityEvents() error = %v, want %v", err, ErrForbidden)
	}

	events, err := service.SecurityEvents(operator)
	if err != nil {
		t.Fatalf("SecurityEvents() operator error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("security event count = %d, want 2", len(events))
	}
	if events[0].ActorID() != client.ID || events[0].Action() != "decision_records_forbidden" {
		t.Errorf("first security event = (%q, %q), want denied decision-record access", events[0].ActorID(), events[0].Action())
	}
	if SecurityEventRetention < 365*24*time.Hour {
		t.Errorf("security event retention = %v, want at least 12 months", SecurityEventRetention)
	}
}
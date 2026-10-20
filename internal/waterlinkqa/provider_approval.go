package waterlinkqa

import (
	"errors"
	"sync"
	"time"
)

type Role string

const (
	RoleClient   Role = "CLIENT"
	RoleProvider Role = "PROVIDER"
	RoleOperator Role = "OPERATOR"
)

type ProviderStatus string

const (
	ProviderPending  ProviderStatus = "PENDING"
	ProviderApproved ProviderStatus = "APPROVED"
	ProviderRejected ProviderStatus = "REJECTED"
)

type Outcome string

const (
	OutcomeApproved Outcome = "APPROVED"
	OutcomeRejected Outcome = "REJECTED"
)

const SecurityEventRetention = 12 * 30 * 24 * time.Hour

var (
	ErrUnauthenticated = errors.New("authentication required")
	ErrForbidden       = errors.New("operator role required")
	ErrSelfApproval    = errors.New("operators cannot decide their own provider status")
	ErrInvalidOutcome  = errors.New("decision outcome must be APPROVED or REJECTED")
	ErrProviderNotPending = errors.New("provider status must be PENDING")
)

type Actor struct {
	ID            string
	Role          Role
	Authenticated bool
}

type Provider struct {
	ID     string
	Status ProviderStatus
}

type Decision struct {
	providerID string
	operatorID string
	outcome    Outcome
	timestamp  time.Time
	reason     string
}

func (d Decision) ProviderID() string {
	return d.providerID
}

func (d Decision) OperatorID() string {
	return d.operatorID
}

func (d Decision) Outcome() Outcome {
	return d.outcome
}

func (d Decision) Timestamp() time.Time {
	return d.timestamp
}

func (d Decision) Reason() string {
	return d.reason
}

type SecurityEvent struct {
	actorID  string
	action   string
	timestamp time.Time
}

func (e SecurityEvent) ActorID() string {
	return e.actorID
}

func (e SecurityEvent) Action() string {
	return e.action
}

func (e SecurityEvent) Timestamp() time.Time {
	return e.timestamp
}

type Service struct {
	mu             sync.Mutex
	now            func() time.Time
	decisions      []Decision
	securityEvents []SecurityEvent
}

func NewService(now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{now: now}
}

func (s *Service) Decide(actor Actor, provider *Provider, outcome Outcome, reason string) (Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !actor.Authenticated {
		s.recordDenial(actor.ID, "provider_decision_unauthenticated")
		return Decision{}, ErrUnauthenticated
	}
	if actor.Role != RoleOperator {
		s.recordDenial(actor.ID, "provider_decision_forbidden")
		return Decision{}, ErrForbidden
	}
	if provider == nil || actor.ID == provider.ID {
		s.recordDenial(actor.ID, "provider_decision_self_approval")
		return Decision{}, ErrSelfApproval
	}
	if outcome != OutcomeApproved && outcome != OutcomeRejected {
		return Decision{}, ErrInvalidOutcome
	}
	if provider.Status != ProviderPending {
		return Decision{}, ErrProviderNotPending
	}

	timestamp := s.now().UTC()
	decision := Decision{
		providerID: provider.ID,
		operatorID: actor.ID,
		outcome:    outcome,
		timestamp:  timestamp,
		reason:     reason,
	}

	provider.Status = ProviderStatus(outcome)
	s.decisions = append(s.decisions, decision)

	return decision, nil
}

func (s *Service) Decisions(actor Actor) ([]Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !actor.Authenticated {
		s.recordDenial(actor.ID, "decision_records_unauthenticated")
		return nil, ErrUnauthenticated
	}
	if actor.Role != RoleOperator {
		s.recordDenial(actor.ID, "decision_records_forbidden")
		return nil, ErrForbidden
	}

	return append([]Decision(nil), s.decisions...), nil
}

func (s *Service) SecurityEvents(actor Actor) ([]SecurityEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !actor.Authenticated {
		s.recordDenial(actor.ID, "security_events_unauthenticated")
		return nil, ErrUnauthenticated
	}
	if actor.Role != RoleOperator {
		s.recordDenial(actor.ID, "security_events_forbidden")
		return nil, ErrForbidden
	}

	return append([]SecurityEvent(nil), s.securityEvents...), nil
}

func (s *Service) recordDenial(actorID, action string) {
	s.securityEvents = append(s.securityEvents, SecurityEvent{
		actorID:   actorID,
		action:    action,
		timestamp: s.now().UTC(),
	})
}
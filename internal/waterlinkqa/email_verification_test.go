package waterlinkqa

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ledger "github.com/formancehq/ledger/internal"
)

func TestEmailVerification(t *testing.T) {
	now := time.Date(2026, time.October, 20, 12, 0, 0, 123000000, time.UTC)
	store := NewAccountStore(filepath.Join(t.TempDir(), "accounts.json"))
	store.now = func() time.Time { return now }

	require.NoError(t, store.Put(ledger.Account{Address: "client:synthetic@example.test"}))
	token, err := store.IssueEmailVerificationToken("client:synthetic@example.test", time.Hour)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	before, err := store.Get("client:synthetic@example.test")
	require.NoError(t, err)
	require.False(t, before.EmailVerified)
	require.NotEmpty(t, before.EmailVerificationTokenHash)
	require.Equal(t, now.Add(time.Hour).UnixMilli(), before.EmailVerificationExpiresAtUTC)

	verified, err := store.VerifyEmail(token)
	require.NoError(t, err)
	require.True(t, verified.EmailVerified)
	require.True(t, verified.EmailVerificationTokenUsed)

	persisted, err := store.Get("client:synthetic@example.test")
	require.NoError(t, err)
	require.True(t, persisted.EmailVerified)

	replayed, err := store.VerifyEmail(token)
	require.ErrorIs(t, err, ErrInvalidVerificationToken)
	require.True(t, replayed.EmailVerified)

	persisted, err = store.Get("client:synthetic@example.test")
	require.NoError(t, err)
	require.True(t, persisted.EmailVerified)
}

func TestEmailVerificationRejectsInvalidAndExpiredTokensWithoutChangingState(t *testing.T) {
	now := time.Date(2026, time.October, 20, 12, 0, 0, 123000000, time.UTC)
	store := NewAccountStore(filepath.Join(t.TempDir(), "accounts.json"))
	store.now = func() time.Time { return now }

	require.NoError(t, store.Put(ledger.Account{Address: "provider:synthetic@example.test"}))
	token, err := store.IssueEmailVerificationToken("provider:synthetic@example.test", time.Hour)
	require.NoError(t, err)

	_, err = store.VerifyEmail("not-the-token")
	require.ErrorIs(t, err, ErrInvalidVerificationToken)

	account, err := store.Get("provider:synthetic@example.test")
	require.NoError(t, err)
	require.False(t, account.EmailVerified)
	require.False(t, account.EmailVerificationTokenUsed)

	store.now = func() time.Time { return now.Add(time.Hour) }
	expired, err := store.VerifyEmail(token)
	require.ErrorIs(t, err, ErrInvalidVerificationToken)
	require.False(t, expired.EmailVerified)
	require.False(t, expired.EmailVerificationTokenUsed)

	account, err = store.Get("provider:synthetic@example.test")
	require.NoError(t, err)
	require.False(t, account.EmailVerified)
	require.False(t, account.EmailVerificationTokenUsed)
}

func TestEmailVerificationHasExactlyOneConcurrentWinner(t *testing.T) {
	now := time.Date(2026, time.October, 20, 12, 0, 0, 123000000, time.UTC)
	store := NewAccountStore(filepath.Join(t.TempDir(), "accounts.json"))
	store.now = func() time.Time { return now }

	require.NoError(t, store.Put(ledger.Account{Address: "commercial:synthetic@example.test"}))
	token, err := store.IssueEmailVerificationToken("commercial:synthetic@example.test", time.Minute)
	require.NoError(t, err)

	const submissions = 16
	start := make(chan struct{})
	var successes atomic.Int32
	var failures atomic.Int32
	var wait sync.WaitGroup
	wait.Add(submissions)

	for range submissions {
		go func() {
			defer wait.Done()
			<-start
			_, err := store.VerifyEmail(token)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrInvalidVerificationToken):
				failures.Add(1)
			default:
				t.Errorf("unexpected verification error: %v", err)
			}
		}()
	}

	close(start)
	wait.Wait()

	require.EqualValues(t, 1, successes.Load())
	require.EqualValues(t, submissions-1, failures.Load())

	account, err := store.Get("commercial:synthetic@example.test")
	require.NoError(t, err)
	require.True(t, account.EmailVerified)
	require.True(t, account.EmailVerificationTokenUsed)
}

func TestIssueEmailVerificationTokenValidation(t *testing.T) {
	store := NewAccountStore(filepath.Join(t.TempDir(), "accounts.json"))

	_, err := store.IssueEmailVerificationToken("missing", time.Hour)
	require.ErrorIs(t, err, ErrAccountNotFound)

	require.NoError(t, store.Put(ledger.Account{Address: "client:synthetic@example.test"}))
	_, err = store.IssueEmailVerificationToken("client:synthetic@example.test", 0)
	require.ErrorIs(t, err, ErrInvalidTokenLifetime)
}
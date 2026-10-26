# Email Verification Replay-Safety Blocker

Implementation is blocked because the existing `internal/waterlinkqa` source files were not provided.

The change must extend the existing email-verification implementation and authoritative `Account` model in `registration.go`. Creating replacement identity, persistence, verification, or security-event types without those sources would risk compilation conflicts and disconnected account state.

Required source context:

- The authoritative `Account` and `ProviderStatus` declarations.
- The existing `AccountStore` interface and file-store implementation.
- Registration, email-verification, provider-approval, and session handlers.
- The existing `SecurityEvent` declaration and event persistence path.
- Existing WaterLink tests and route construction.

The eventual implementation must:

- Resolve one `CLIENT` or `PROVIDER` account from the submitted token.
- Use an injectable server-controlled UTC clock truncated to millisecond precision.
- Accept only when `now < expiresAt`.
- Atomically consume the token and set the shared account's `verified` state.
- Leave account and token state unchanged for malformed, unknown, expired, and exact-expiry submissions.
- Reject replay while preserving `verified=true`.
- Produce exactly one durable winner for concurrent submissions.
- Persist `consumedAt` and only non-secret synthetic references, outcome, and UTC event timestamp.
- Never persist, log, or return the submitted bearer token.
- Continue using server-side session identity rather than client-supplied roles or verification flags.
- Preserve existing retention, deletion, access-control, monitoring, and audit behavior without inventing a retention duration or compliance claim.

No implementation tests were added or run because the APIs and shared persisted state needed to construct valid tests are unavailable.
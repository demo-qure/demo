package v2

import (
	"encoding/base64"
	"math/big"
	"net/http"

	"github.com/formancehq/go-libs/v5/pkg/transport/api"
	"github.com/formancehq/go-libs/v5/pkg/types/metadata"

	ledger "github.com/formancehq/ledger/internal"
	"github.com/formancehq/ledger/internal/api/common"
	ledgercontroller "github.com/formancehq/ledger/internal/controller/ledger"
)

type releaseReadinessConfirmation struct {
	Outcome      string  `json:"outcome"`
	Confirmation string  `json:"confirmation"`
	LogID        *uint64 `json:"logID"`
	LogHash      string  `json:"logHash"`
}

func recordReleaseReadinessOutcome(w http.ResponseWriter, r *http.Request) {
	l := common.LedgerFromContext(r.Context())

	txData := ledger.NewTransactionData().
		WithPostings(ledger.NewPosting(
			"world",
			"sukukflow:reporting:release-readiness",
			"SUKUK-DEMO",
			big.NewInt(1),
		)).
		WithMetadata(metadata.Metadata{
			"workflow": "reporting-and-release-readiness",
			"outcome":  "successful",
			"purpose":  "synthetic-demo",
		})

	log, _, idempotencyHit, err := l.CreateTransaction(r.Context(), getCommandParameters(r, ledgercontroller.CreateTransaction{
		RunScript: ledgercontroller.TxToScriptData(txData, false),
	}))
	if err != nil {
		common.HandleCommonWriteErrors(w, r, err)
		return
	}
	if idempotencyHit {
		w.Header().Set("Idempotency-Hit", "true")
	}

	api.Ok(w, releaseReadinessConfirmation{
		Outcome:      "successful",
		Confirmation: "Synthetic reporting and release readiness outcome recorded.",
		LogID:        log.ID,
		LogHash:      base64.RawURLEncoding.EncodeToString(log.Hash),
	})
}
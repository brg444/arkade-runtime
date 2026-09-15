package application

import (
	"errors"
	"testing"

	"github.com/brg444/arkade-runtime/internal/apperr"
	"github.com/brg444/arkade-runtime/internal/policy"
)

func TestPrepareRejectionClassifiesBoundedReasons(t *testing.T) {
	active := prepareRejection(policy.ErrVtxoOperationActive)
	classified := apperr.Of(active)
	if classified.Code != apperr.CodeRejected || classified.Msg == "" || classified.Msg == "request rejected" {
		t.Fatalf("active-operation rejection was not classified: %#v", classified)
	}
	if got := publicErrorMessage(apperr.CodeRejected, active); got != classified.Msg {
		t.Fatalf("classified reason is not exposed, got %q", got)
	}

	allowance := prepareRejection(policy.ErrPeriodAllowanceExceeded)
	if msg := apperr.Of(allowance).Msg; msg == "" || msg == "request rejected" {
		t.Fatalf("allowance rejection was not classified")
	}

	// A dependency/infrastructure error must stay unclassified and redacted.
	dependency := errors.New("dial tcp 127.0.0.1:8080: connection refused")
	if got := prepareRejection(dependency); got != dependency {
		t.Fatalf("dependency error must pass through unchanged, got %v", got)
	}
	if got := publicErrorMessage(apperr.CodeRejected, dependency); got != "request rejected" {
		t.Fatalf("dependency error must stay redacted, got %q", got)
	}
}

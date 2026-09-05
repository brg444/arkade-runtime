package policy

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpenEnrollmentIssuanceIsBoundedAcrossConcurrentRequests(t *testing.T) {
	now := time.Now().UTC()
	ledger := openPolicyTestLedger(t, func() time.Time { return now })
	var issued atomic.Int32
	var group sync.WaitGroup
	for i := range 50 {
		group.Go(func() {
			hash := sha256.Sum256(fmt.Appendf(nil, "session-%d", i))
			expires, err := ledger.IssueEnrollmentSession(hash[:], now)
			if err == nil {
				if !expires.Equal(now.Add(10 * time.Minute)) {
					t.Error("wrong session expiry")
				}
				issued.Add(1)
			}
		})
	}
	group.Wait()
	if issued.Load() != 30 {
		t.Fatalf("issued %d sessions, want 30", issued.Load())
	}
	hash := sha256.Sum256([]byte("later-session"))
	if _, err := ledger.IssueEnrollmentSession(hash[:], now.Add(61*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestOpenEnrollmentSessionsExpireAndDoNotOverwriteInvites(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ledger := openPolicyTestLedger(t, func() time.Time { return now })
	hash := sha256.Sum256([]byte("one-session"))
	if _, err := ledger.IssueEnrollmentSession(hash[:], now); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.IssueEnrollmentSession(hash[:], now); err == nil {
		t.Fatal("replaced an existing token")
	}
	invite, err := ledger.GetInvite(hash[:])
	if err != nil || !invite.Usable(now) || invite.Usable(now.Add(11*time.Minute)) {
		t.Fatal("session expiry was not enforced")
	}
	if _, err := ledger.IssueEnrollmentSession([]byte("short"), now); err == nil {
		t.Fatal("accepted invalid token hash")
	}
}

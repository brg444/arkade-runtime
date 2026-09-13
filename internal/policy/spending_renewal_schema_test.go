package policy

import (
	"path/filepath"
	"testing"
)

func TestSpendingRenewalSchemaRejectsDriftOnRestart(t *testing.T) {
	for _, mutation := range []string{
		`ALTER TABLE light_renewal_event ADD COLUMN junk TEXT`,
		`DROP TABLE light_renewal_event`,
		`CREATE INDEX hidden_phase ON light_renewal_event(phase)`,
		`CREATE TRIGGER erase_renewals AFTER INSERT ON light_renewal_event BEGIN DELETE FROM light_renewal_operation; END`,
	} {
		t.Run(mutation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "current.sqlite")
			l, err := OpenLedger(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := l.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			l.Close()
			if accepted, err := OpenLedger(path, nil); err == nil {
				accepted.Close()
				t.Fatal("renewal schema drift accepted")
			}
		})
	}
}

package policy

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Delegation stores owner-presigned authorization separately from input ownership.
// Armed requests have no spending authority from Guardian and consume no allowance.
type LightDelegation struct {
	OperationID string `json:"operationId"`
	VaultID     string `json:"vaultId"`
	InputTxid   string `json:"inputTxid"`
	InputVout   uint32 `json:"inputVout"`
	ValidAt     int64  `json:"validAt"`
	ExpiresAt   int64  `json:"expiresAt"`
	FeeSats     int64  `json:"feeSats"`
	PlanDigest  string `json:"planDigest"`
	Plan        string `json:"plan"`
	CreatedAt   string `json:"createdAt"`
}
type LightDelegationEvent struct {
	OperationID string `json:"operationId"`
	Phase       string `json:"phase"`
	Evidence    string `json:"evidence"`
	CreatedAt   string `json:"createdAt"`
}
type LightDelegationSnapshot struct {
	Operation LightDelegation
	Events    map[string]LightDelegationEvent
}

var delegationPhases = []string{"claimed", "register_authorized", "register_dispatched", "register_result", "batch_started", "tree_prepared", "nonces_committed", "tree_signed", "final_authorized", "final_dispatched", "final_result", "cleanup_pending", "cleanup_authorized", "cleanup_dispatched", "cleanup_result", "confirmed", "invalidated", "cancelled", "expired", "needs_authorization", "rejected"}

func delegationTerminal(s *LightDelegationSnapshot) bool {
	for _, p := range []string{"confirmed", "invalidated", "cancelled", "expired", "needs_authorization", "rejected"} {
		if _, ok := s.Events[p]; ok {
			return true
		}
	}
	return false
}
func (s *LightDelegationSnapshot) State() string {
	state := "armed"
	for _, p := range delegationPhases {
		if _, ok := s.Events[p]; ok {
			state = p
			if strings.HasPrefix(p, "cleanup_") {
				state = "cleanup_pending"
			}
		}
	}
	return state
}
func validateDelegation(o LightDelegation) error {
	created, err := time.Parse(time.RFC3339, o.CreatedAt)
	if err != nil || !canonicalRenewalHex(o.OperationID, 16) || !canonicalRenewalHex(o.VaultID, 32) || !canonicalRenewalHex(o.InputTxid, 32) || !canonicalRenewalHex(o.PlanDigest, 32) || o.FeeSats < 0 || o.FeeSats > 20000 || o.ValidAt < created.Unix() || o.ValidAt > created.Add(30*24*time.Hour).Unix() || o.ExpiresAt <= o.ValidAt || o.ExpiresAt > o.ValidAt+86400 || len(o.Plan) == 0 || len(o.Plan) > 65536 || !json.Valid([]byte(o.Plan)) {
		return fmt.Errorf("invalid Light delegation")
	}
	return nil
}
func validateDelegationEvent(e LightDelegationEvent) error {
	if !canonicalRenewalHex(e.OperationID, 16) || len(e.Evidence) > 4_000_000 || !json.Valid([]byte(e.Evidence)) {
		return fmt.Errorf("invalid Light delegation event")
	}
	if _, err := time.Parse(time.RFC3339, e.CreatedAt); err != nil {
		return err
	}
	if validDelegationStreamPhase(e.Phase) {
		if len(e.Evidence) > 131072 {
			return fmt.Errorf("Light delegation stream event too large")
		}
		return nil
	}
	for _, p := range delegationPhases {
		if e.Phase == p {
			return nil
		}
	}
	return fmt.Errorf("unknown Light delegation phase")
}
func validDelegationStreamPhase(phase string) bool {
	if phase == "stream_signing_started" || phase == "stream_finalization" {
		return true
	}
	for _, prefix := range []string{"stream_tree_0_", "stream_tree_1_", "stream_nonce_", "stream_signature_"} {
		if strings.HasPrefix(phase, prefix) {
			return canonicalRenewalHex(strings.TrimPrefix(phase, prefix), 32)
		}
	}
	return false
}
func loadLightDelegations(ctx context.Context, q queryContext, key []byte) (map[string]*LightDelegationSnapshot, error) {
	rows, err := q.QueryContext(ctx, `SELECT operation_id,vault_id,payload,integrity_mac FROM light_delegation_operation`)
	if err != nil {
		return nil, err
	}
	all := map[string]*LightDelegationSnapshot{}
	for rows.Next() {
		var id, vault, payload string
		var mac []byte
		if err := rows.Scan(&id, &vault, &payload, &mac); err != nil {
			rows.Close()
			return nil, err
		}
		var o LightDelegation
		if len(payload) > 131072 || !hmac.Equal(mac, renewalMAC(key, "vaulted-light/delegation-operation/v1", payload)) || json.Unmarshal([]byte(payload), &o) != nil {
			rows.Close()
			return nil, fmt.Errorf("Light delegation integrity")
		}
		canonical, _ := json.Marshal(o)
		if string(canonical) != payload || o.OperationID != id || o.VaultID != vault || validateDelegation(o) != nil {
			rows.Close()
			return nil, fmt.Errorf("Light delegation binding")
		}
		all[id] = &LightDelegationSnapshot{o, map[string]LightDelegationEvent{}}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = q.QueryContext(ctx, `SELECT operation_id,phase,payload,integrity_mac FROM light_delegation_event`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, phase, payload string
		var mac []byte
		if err := rows.Scan(&id, &phase, &payload, &mac); err != nil {
			return nil, err
		}
		var e LightDelegationEvent
		if len(payload) > 8_000_000 || !hmac.Equal(mac, renewalMAC(key, "vaulted-light/delegation-event/v1", payload)) || json.Unmarshal([]byte(payload), &e) != nil {
			return nil, fmt.Errorf("Light delegation event integrity")
		}
		canonical, _ := json.Marshal(e)
		if string(canonical) != payload || e.OperationID != id || e.Phase != phase || all[id] == nil || validateDelegationEvent(e) != nil {
			return nil, fmt.Errorf("Light delegation event binding")
		}
		all[id].Events[phase] = e
	}
	return all, rows.Err()
}
func (l *Ledger) ListLightDelegations(ctx context.Context) ([]LightDelegationSnapshot, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	all, err := loadLightDelegations(ctx, l.db, key)
	if err != nil {
		return nil, err
	}
	if err := l.observeEconomicOutflowsLocked(l.db); err != nil {
		return nil, err
	}
	out := make([]LightDelegationSnapshot, 0, len(all))
	for _, s := range all {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Operation.OperationID < out[j].Operation.OperationID })
	return out, nil
}
func (l *Ledger) ScheduleLightDelegation(ctx context.Context, o LightDelegation) (*LightDelegationSnapshot, error) {
	o.CreatedAt = l.NowUTC().Format(time.RFC3339)
	var out *LightDelegationSnapshot
	err := l.withLightRenewalTx(ctx, func(tx *sql.Conn, key []byte) error {
		all, err := loadLightDelegations(ctx, tx, key)
		if err != nil {
			return err
		}
		// Check the existing sequence before inserting a replacement row. Otherwise
		// deletion followed by insertion could restore the count and hide rollback.
		if err := l.observeEconomicOutflowsLocked(tx); err != nil {
			return err
		}
		if old := all[o.OperationID]; old != nil {
			copy := o
			copy.CreatedAt = old.Operation.CreatedAt
			if copy != old.Operation {
				return fmt.Errorf("Light delegation operation already bound")
			}
			out = old
			return nil
		}
		if err := validateDelegation(o); err != nil {
			return err
		}
		active := 0
		for _, s := range all {
			if s.Operation.VaultID != o.VaultID || delegationTerminal(s) {
				continue
			}
			active++
			if s.Operation.InputTxid == o.InputTxid && s.Operation.InputVout == o.InputVout {
				return ErrVtxoOperationActive
			}
		}
		if active >= 256 {
			return fmt.Errorf("Light delegation capacity reached")
		}
		if err := l.rejectDelegationPaymentOverlap(ctx, tx, key, o); err != nil {
			return err
		}
		if err := l.rejectActiveLightRenewal(ctx, tx, o.VaultID); err != nil {
			return err
		}
		payload, _ := json.Marshal(o)
		_, err = tx.ExecContext(ctx, `INSERT INTO light_delegation_operation VALUES(?,?,?,?)`, o.OperationID, o.VaultID, string(payload), renewalMAC(key, "vaulted-light/delegation-operation/v1", string(payload)))
		out = &LightDelegationSnapshot{o, map[string]LightDelegationEvent{}}
		return err
	})
	return out, err
}
func insertDelegationEvent(ctx context.Context, tx *sql.Conn, key []byte, e LightDelegationEvent) error {
	if err := validateDelegationEvent(e); err != nil {
		return err
	}
	payload, _ := json.Marshal(e)
	_, err := tx.ExecContext(ctx, `INSERT INTO light_delegation_event VALUES(?,?,?,?)`, e.OperationID, e.Phase, string(payload), renewalMAC(key, "vaulted-light/delegation-event/v1", string(payload)))
	return err
}
func (l *Ledger) AdvanceLightDelegation(ctx context.Context, e LightDelegationEvent, allowance int64) (*LightDelegationSnapshot, error) {
	e.CreatedAt = l.NowUTC().Format(time.RFC3339)
	var out *LightDelegationSnapshot
	err := l.withLightRenewalTx(ctx, func(tx *sql.Conn, key []byte) error {
		all, err := loadLightDelegations(ctx, tx, key)
		if err != nil {
			return err
		}
		// Check the existing sequence before inserting a replacement row. Otherwise
		// deletion followed by insertion could restore the count and hide rollback.
		if err := l.observeEconomicOutflowsLocked(tx); err != nil {
			return err
		}
		s := all[e.OperationID]
		if s == nil {
			return fmt.Errorf("Light delegation unavailable")
		}
		if delegationTerminal(s) && e.Phase != s.State() {
			return fmt.Errorf("Light delegation terminal")
		}
		if _, abandoned := s.Events["cleanup_pending"]; abandoned && !strings.HasPrefix(e.Phase, "cleanup_") && e.Phase != "expired" {
			return fmt.Errorf("Light delegation abandoned")
		}
		if old, ok := s.Events[e.Phase]; ok {
			copy := e
			copy.CreatedAt = old.CreatedAt
			if copy != old {
				return fmt.Errorf("Light delegation phase already bound")
			}
			out = s
			return nil
		}
		if delegationTerminal(s) {
			return fmt.Errorf("Light delegation terminal")
		}
		require := func(phase string) error {
			if _, ok := s.Events[phase]; !ok {
				return fmt.Errorf("Light delegation requires %s", phase)
			}
			return nil
		}
		switch e.Phase {
		case "expired", "cleanup_pending":
			if _, final := s.Events["final_authorized"]; final {
				return fmt.Errorf("Light delegation final authorization cannot expire")
			}
			if !VaultBoardRegisterCanSupersede(s.Operation.ExpiresAt, l.NowUTC()) {
				return fmt.Errorf("Light delegation expiry quarantine")
			}
			if e.Phase == "expired" {
				if _, dispatched := s.Events["register_dispatched"]; dispatched {
					if _, cleared := s.Events["cleanup_result"]; !cleared {
						return fmt.Errorf("Light delegation Operator cleanup required")
					}
				}
			}
		case "cancelled", "invalidated", "needs_authorization":
			_, claimed := s.Events["claimed"]
			if len(s.Events) != 0 && !(e.Phase == "needs_authorization" && len(s.Events) == 1 && claimed) {
				return fmt.Errorf("Light delegation already owns inputs")
			}

		case "claimed":
			if len(s.Events) != 0 || l.NowUTC().Unix() < s.Operation.ValidAt || l.NowUTC().Unix() >= s.Operation.ExpiresAt {
				return fmt.Errorf("Light delegation outside dispatch window")
			}
			for _, other := range all {
				if other.Operation.VaultID == s.Operation.VaultID && !delegationTerminal(other) && len(other.Events) > 0 {
					return ErrVtxoOperationActive
				}
			}
			if err := l.rejectConcurrentVtxoOperationLocked(ctx, tx, s.Operation.VaultID, ""); err != nil {
				return err
			}
			if err := l.rejectActiveLightRenewal(ctx, tx, s.Operation.VaultID); err != nil {
				return err
			}
			used, err := l.spentInWindow(ctx, tx, s.Operation.VaultID)
			if err != nil {
				return err
			}
			if allowance < 0 || used > allowance || s.Operation.FeeSats > allowance-used {
				return ErrPeriodAllowanceExceeded
			}
		case "rejected":
			if err := require("register_dispatched"); err != nil {
				return err
			}
			if _, ok := s.Events["register_result"]; ok {
				return fmt.Errorf("registered delegation cannot be rejected")
			}
		default:
			if e.Phase == "final_authorized" && l.NowUTC().Unix() >= s.Operation.ExpiresAt {
				return fmt.Errorf("Light delegation final authorization expired")
			}
			predecessors := map[string]string{"register_authorized": "claimed", "register_dispatched": "register_authorized", "register_result": "register_dispatched", "batch_started": "register_result", "tree_prepared": "batch_started", "nonces_committed": "tree_prepared", "tree_signed": "nonces_committed", "final_authorized": "tree_signed", "final_dispatched": "final_authorized", "final_result": "final_dispatched", "confirmed": "final_authorized", "cleanup_authorized": "cleanup_pending", "cleanup_dispatched": "cleanup_authorized", "cleanup_result": "cleanup_dispatched"}
			p, ok := predecessors[e.Phase]
			if validDelegationStreamPhase(e.Phase) {
				if len(s.Events) >= 2064 {
					return fmt.Errorf("Light delegation transcript capacity")
				}
				p = "batch_started"
				ok = true
				if strings.HasPrefix(e.Phase, "stream_nonce_") {
					p = "tree_prepared"
				}
				if strings.HasPrefix(e.Phase, "stream_signature_") || e.Phase == "stream_finalization" {
					p = "tree_signed"
				}
			}
			if !ok {
				return fmt.Errorf("unknown delegation transition")
			}
			if err := require(p); err != nil {
				return err
			}
		}
		if err := insertDelegationEvent(ctx, tx, key, e); err != nil {
			return err
		}
		s.Events[e.Phase] = e
		out = s
		return nil
	})
	return out, err
}

// Payment reservation and armed invalidation share the reservation transaction.
func (l *Ledger) invalidateArmedDelegations(ctx context.Context, tx *sql.Conn, vault string, inputs []VtxoOperationInput) error {
	key, err := l.integrityKeyCopy()
	if err != nil {
		return err
	}
	defer zeroBytes(key)
	all, err := loadLightDelegations(ctx, tx, key)
	if err != nil {
		return err
	}
	for _, s := range all {
		if s.Operation.VaultID != vault || delegationTerminal(s) {
			continue
		}
		if len(s.Events) > 0 {
			return ErrVtxoOperationActive
		}
		for _, in := range inputs {
			if hex.EncodeToString(in.Txid) == s.Operation.InputTxid && in.Vout >= 0 && uint32(in.Vout) == s.Operation.InputVout {
				if err := insertDelegationEvent(ctx, tx, key, LightDelegationEvent{s.Operation.OperationID, "invalidated", `{"reason":"payment reservation"}`, l.NowUTC().Format(time.RFC3339)}); err != nil {
					return err
				}
				break
			}
		}
	}
	return nil
}
func (l *Ledger) delegationAllowance(ctx context.Context, q queryContext, vault string, key []byte) (int64, error) {
	all, err := loadLightDelegations(ctx, q, key)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, s := range all {
		if s.Operation.VaultID != vault || len(s.Events) == 0 {
			continue
		}
		if delegationTerminal(s) {
			e, ok := s.Events["confirmed"]
			if !ok {
				continue
			}
			at, _ := time.Parse(time.RFC3339, e.CreatedAt)
			if l.NowUTC().After(at.Add(allowanceWindow)) {
				continue
			}
		}
		if total > (1<<63-1)-s.Operation.FeeSats {
			return 0, fmt.Errorf("delegation allowance overflow")
		}
		total += s.Operation.FeeSats
	}
	return total, nil
}
func (l *Ledger) rejectDispatchedDelegation(ctx context.Context, q queryContext, vault string) error {
	key, err := l.integrityKeyCopy()
	if err != nil {
		return err
	}
	defer zeroBytes(key)
	all, err := loadLightDelegations(ctx, q, key)
	if err != nil {
		return err
	}
	for _, s := range all {
		if s.Operation.VaultID == vault && len(s.Events) > 0 && !delegationTerminal(s) {
			return ErrVtxoOperationActive
		}
	}
	return nil
}

// Scheduling does not acquire signing authority. It may coexist with a payment
// using another input; dispatch still requires exclusive ownership of the vault.
func (l *Ledger) rejectDelegationPaymentOverlap(ctx context.Context, q queryContext, key []byte, o LightDelegation) error {
	rows, err := q.QueryContext(ctx, `SELECT `+vtxoSelectColumns+` FROM vtxo_operation`)
	if err != nil {
		return err
	}
	active := map[string]bool{}
	for rows.Next() {
		rec, err := scanVtxoOperation(rows)
		if err == nil {
			err = VerifyVtxoOperation(&rec, key)
		}
		if err != nil {
			rows.Close()
			return err
		}
		if rec.VaultID == o.VaultID && vtxoStateBlocksNewOperation(rec.State) {
			active[rec.OperationID] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// Authenticate correlation before filtering; a tampered input's operation ID
	// must not hide an overlap with a live reservation.
	rows, err = q.QueryContext(ctx, `SELECT operation_id,txid,vout,value_sats,script,integrity_mac FROM vtxo_operation_input`)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := map[string]bool{}
	overlap := false
	for rows.Next() {
		var in VtxoOperationInput
		if err := rows.Scan(&in.OperationID, &in.Txid, &in.Vout, &in.ValueSats, &in.Script, &in.IntegrityMAC); err != nil {
			return err
		}
		if err := VerifyVtxoOperationInput(&in, key); err != nil {
			return err
		}
		if active[in.OperationID] {
			found[in.OperationID] = true
			if hex.EncodeToString(in.Txid) == o.InputTxid && int64(o.InputVout) == int64(in.Vout) {
				overlap = true
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if overlap || len(found) != len(active) {
		return ErrVtxoOperationActive
	}
	return nil
}

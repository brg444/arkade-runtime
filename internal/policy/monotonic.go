package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const monotonicFileVersion = "arkade-vault-policy-sequence/v2"

// Monotonic is the policy-ledger sequence stored outside SQLite. Every new
// economic-outflow reservation advances it. Restoring an older database while
// retaining this file is refused. A matched rollback of both files defeats
// this in-process control, so restore tooling treats them as one coherent unit
// while operations retain an external accepted-count record.
type Monotonic struct {
	path string
	key  []byte
	mu   sync.Mutex
}

func OpenMonotonic(path string, integrityKey []byte) (*Monotonic, error) {
	if path == "" {
		return nil, fmt.Errorf("monotonic path required")
	}
	if len(integrityKey) != sha256.Size {
		return nil, fmt.Errorf("integrity key required")
	}
	return &Monotonic{path: path, key: append([]byte(nil), integrityKey...)}, nil
}

func (m *Monotonic) Observe(dbCount uint64) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fileCount, exists, err := m.read()
	if err != nil {
		return err
	}
	if !exists {
		if dbCount != 0 {
			return fmt.Errorf("policy sequence is missing for a non-empty policy ledger")
		}
		return m.write(0)
	}
	if dbCount < fileCount {
		return fmt.Errorf("policy ledger is behind the external sequence (%d < %d); refuse to start from a rolled-back database", dbCount, fileCount)
	}
	if dbCount == fileCount {
		return nil
	}
	return m.write(dbCount)
}

// VerifyExact authenticates the persisted policy sequence and requires it to
// match the database without repairing or advancing either artifact. Restore
// tooling uses this read-only check before a state unit can be accepted.
func (m *Monotonic) VerifyExact(dbCount uint64) (uint64, error) {
	if m == nil {
		return 0, fmt.Errorf("monotonic policy sequence required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fileCount, exists, err := m.read()
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, fmt.Errorf("policy sequence is missing")
	}
	if dbCount < fileCount {
		return fileCount, fmt.Errorf("policy ledger is behind the external sequence (%d < %d); refuse to restore a rolled-back database", dbCount, fileCount)
	}
	if dbCount > fileCount {
		return fileCount, fmt.Errorf("policy sequence is behind the policy ledger (%d < %d); refuse to restore a rolled-back sequence", fileCount, dbCount)
	}
	return fileCount, nil
}

func (m *Monotonic) read() (uint64, bool, error) {
	raw, err := os.ReadFile(m.path)
	if os.IsNotExist(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	count, mac, err := parseMonotonic(raw)
	if err != nil {
		return 0, true, err
	}
	if !hmac.Equal(mac, m.mac(count)) {
		return 0, true, fmt.Errorf("monotonic counter MAC mismatch")
	}
	return count, true, nil
}

func (m *Monotonic) write(count uint64) error {
	body := fmt.Sprintf("%s\ncount=%d\n", monotonicFileVersion, count)
	mac := m.mac(count)
	tmp := m.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmp)
		}
	}()
	payload := []byte(body + fmt.Sprintf("mac=%x\n", mac))
	if _, err := f.Write(payload); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, m.path); err != nil {
		return err
	}
	removeTmp = false
	dir, err := os.Open(filepath.Dir(m.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (m *Monotonic) mac(count uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], count)
	h := hmac.New(sha256.New, m.key)
	_, _ = h.Write([]byte(monotonicMACDomain))
	_, _ = h.Write(buf[:])
	return h.Sum(nil)
}

func parseMonotonic(raw []byte) (uint64, []byte, error) {
	lines := strings.Split(string(raw), "\n")
	if len(lines) < 3 || lines[0] != monotonicFileVersion {
		return 0, nil, fmt.Errorf("monotonic counter version")
	}
	var count uint64
	var mac []byte
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "count=") {
			n, err := strconv.ParseUint(strings.TrimPrefix(line, "count="), 10, 64)
			if err != nil {
				return 0, nil, fmt.Errorf("monotonic counter")
			}
			count = n
		}
		if strings.HasPrefix(line, "mac=") {
			got, err := parseHexMAC(strings.TrimPrefix(line, "mac="))
			if err != nil {
				return 0, nil, err
			}
			mac = got
		}
	}
	if len(mac) != sha256.Size {
		return 0, nil, fmt.Errorf("monotonic counter MAC missing")
	}
	return count, mac, nil
}

func parseHexMAC(s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, fmt.Errorf("monotonic counter MAC")
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		a := unhex(s[i*2])
		b := unhex(s[i*2+1])
		if a < 0 || b < 0 {
			return nil, fmt.Errorf("monotonic counter MAC")
		}
		out[i] = byte(a<<4 | b)
	}
	return out, nil
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	default:
		return -1
	}
}

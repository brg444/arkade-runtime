package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

const monotonicFileVersion = "arkade-vault-policy-sequence/v2"

// Monotonic is the policy-ledger sequence stored outside SQLite. Every new
// economic-outflow reservation advances it. Restoring an older database while
// retaining this file is refused. Restoring both files together defeats this
// control, so production must protect them as separate failure domains.
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
	fileCount, err := m.read()
	if err != nil {
		return err
	}
	if dbCount < fileCount {
		return fmt.Errorf("policy ledger is behind the external sequence (%d < %d); refuse to start from a rolled-back database", dbCount, fileCount)
	}
	if dbCount == fileCount {
		return nil
	}
	return m.write(dbCount)
}

func (m *Monotonic) read() (uint64, error) {
	raw, err := os.ReadFile(m.path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	count, mac, err := parseMonotonic(raw)
	if err != nil {
		return 0, err
	}
	if !hmac.Equal(mac, m.mac(count)) {
		return 0, fmt.Errorf("monotonic counter MAC mismatch")
	}
	return count, nil
}

func (m *Monotonic) write(count uint64) error {
	body := fmt.Sprintf("%s\ncount=%d\n", monotonicFileVersion, count)
	mac := m.mac(count)
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body+fmt.Sprintf("mac=%x\n", mac)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
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

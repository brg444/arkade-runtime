package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

var ErrClosed = errors.New("Arkade Runtime is closed")

type State string

const (
	StateOpen    State = "open"
	StateClosing State = "closing"
	StateClosed  State = "closed"
)

// Mount adapts one existing application into the runtime lifecycle. The
// handler is returned unchanged; Arkade Runtime adds no HTTP discovery or
// generic signing surface.
type Mount struct {
	Handler   http.Handler
	Readiness func(context.Context) error
	Shutdown  func() error
}

// Host owns one selected compiled profile for a process lifetime.
type Host struct {
	profile Profile
	mount   Mount

	mu       sync.RWMutex
	state    State
	closeErr error
	close    sync.Once
}

func Open(registry *Registry, profileID string, mount Mount) (*Host, error) {
	if registry == nil {
		return nil, fmt.Errorf("Arkade Runtime registry required")
	}
	profile, ok := registry.Profile(profileID)
	if !ok {
		return nil, fmt.Errorf("Arkade Runtime profile %q is not compiled", profileID)
	}
	if mount.Handler == nil {
		return nil, fmt.Errorf("Arkade Runtime handler required")
	}
	if mount.Readiness == nil {
		return nil, fmt.Errorf("Arkade Runtime readiness required")
	}
	if mount.Shutdown == nil {
		return nil, fmt.Errorf("Arkade Runtime shutdown required")
	}
	return &Host{profile: profile, mount: mount, state: StateOpen}, nil
}

// Handler returns the exact mounted application handler while the host is
// open. Existing middleware, route matching, and JSON behavior are untouched.
func (h *Host) Handler() http.Handler {
	if h == nil {
		return http.NotFoundHandler()
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.state != StateOpen {
		return http.NotFoundHandler()
	}
	return h.mount.Handler
}

func (h *Host) Ready(ctx context.Context) error {
	if h == nil {
		return ErrClosed
	}
	h.mu.RLock()
	state := h.state
	readiness := h.mount.Readiness
	h.mu.RUnlock()
	if state != StateOpen {
		return ErrClosed
	}
	return readiness(ctx)
}

func (h *Host) Profile() Profile {
	if h == nil {
		return Profile{}
	}
	return Profile{definition: cloneDefinition(h.profile.definition)}
}

func (h *Host) State() State {
	if h == nil {
		return StateClosed
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.state
}

// Close invokes the mounted shutdown exactly once and waits for a concurrent
// close to finish. The first shutdown result is stable across repeated calls.
func (h *Host) Close() error {
	if h == nil {
		return nil
	}
	h.close.Do(func() {
		h.mu.Lock()
		h.state = StateClosing
		shutdown := h.mount.Shutdown
		h.mu.Unlock()

		err := shutdown()

		h.mu.Lock()
		h.closeErr = err
		h.state = StateClosed
		h.mu.Unlock()
	})
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.closeErr
}

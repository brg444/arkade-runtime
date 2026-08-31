// Package runtime provides the small compiled Arkade Runtime shell. It owns
// profile registration and lifecycle only; named-program behavior remains in
// the mounted application until it is extracted behind scoped internal ports.
package runtime

import (
	"fmt"
	"sort"
	"strings"
)

// Route is one method and path owned by a compiled profile.
type Route struct {
	Method string
	Path   string
}

// ModuleDefinition is compile-time metadata for one internal module. Stores
// and key scopes are semantic identifiers, not generic KV or signing APIs.
type ModuleDefinition struct {
	ID        string
	Programs  []string
	Policies  []string
	Stores    []string
	KeyScopes []string
}

// ProfileDefinition is one product composition linked into the binary.
type ProfileDefinition struct {
	ID      string
	Modules []ModuleDefinition
	Routes  []Route
}

// Profile is an immutable compiled profile snapshot.
type Profile struct {
	definition ProfileDefinition
}

func (p Profile) ID() string {
	return p.definition.ID
}

func (p Profile) Modules() []ModuleDefinition {
	return cloneDefinition(p.definition).Modules
}

func (p Profile) Routes() []Route {
	return append([]Route(nil), p.definition.Routes...)
}

// Registry is the immutable set of profiles compiled into a process.
type Registry struct {
	profiles map[string]Profile
}

// Compile validates every identifier before a profile can be mounted. There
// is intentionally no dynamic registration or external discovery surface.
func Compile(definitions ...ProfileDefinition) (*Registry, error) {
	if len(definitions) == 0 {
		return nil, fmt.Errorf("runtime registry: at least one profile is required")
	}
	registry := &Registry{profiles: make(map[string]Profile, len(definitions))}
	seen := map[string]map[string]string{
		"module":    {},
		"program":   {},
		"policy":    {},
		"route":     {},
		"store":     {},
		"key scope": {},
	}
	for _, source := range definitions {
		definition := cloneDefinition(source)
		if err := validIdentifier("profile", definition.ID); err != nil {
			return nil, err
		}
		if _, exists := registry.profiles[definition.ID]; exists {
			return nil, fmt.Errorf("runtime registry: duplicate profile %q", definition.ID)
		}
		if len(definition.Modules) == 0 {
			return nil, fmt.Errorf("runtime registry: profile %q has no modules", definition.ID)
		}
		if len(definition.Routes) == 0 {
			return nil, fmt.Errorf("runtime registry: profile %q has no routes", definition.ID)
		}
		for i := range definition.Modules {
			module := &definition.Modules[i]
			if err := claimIdentifier(seen, "module", module.ID, definition.ID); err != nil {
				return nil, err
			}
			if len(module.Programs) == 0 && len(module.Policies) == 0 {
				return nil, fmt.Errorf("runtime registry: module %q has no programs or policies", module.ID)
			}
			for _, id := range module.Programs {
				if err := claimIdentifier(seen, "program", id, module.ID); err != nil {
					return nil, err
				}
			}
			for _, id := range module.Policies {
				if err := claimIdentifier(seen, "policy", id, module.ID); err != nil {
					return nil, err
				}
			}
			for _, id := range module.Stores {
				if err := claimIdentifier(seen, "store", id, module.ID); err != nil {
					return nil, err
				}
			}
			for _, id := range module.KeyScopes {
				if err := claimIdentifier(seen, "key scope", id, module.ID); err != nil {
					return nil, err
				}
			}
		}
		for _, route := range definition.Routes {
			if route.Method == "" || route.Method != strings.ToUpper(route.Method) || strings.TrimSpace(route.Method) != route.Method {
				return nil, fmt.Errorf("runtime registry: profile %q has invalid route method %q", definition.ID, route.Method)
			}
			if route.Path == "" || route.Path[0] != '/' || strings.TrimSpace(route.Path) != route.Path || strings.ContainsAny(route.Path, "?#") {
				return nil, fmt.Errorf("runtime registry: profile %q has invalid route path %q", definition.ID, route.Path)
			}
			key := route.Method + " " + route.Path
			if err := claimIdentifier(seen, "route", key, definition.ID); err != nil {
				return nil, err
			}
		}
		registry.profiles[definition.ID] = Profile{definition: definition}
	}
	return registry, nil
}

func (r *Registry) Profile(id string) (Profile, bool) {
	if r == nil {
		return Profile{}, false
	}
	profile, ok := r.profiles[id]
	if !ok {
		return Profile{}, false
	}
	return Profile{definition: cloneDefinition(profile.definition)}, true
}

func (r *Registry) ProfileIDs() []string {
	if r == nil {
		return nil
	}
	ids := make([]string, 0, len(r.profiles))
	for id := range r.profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func claimIdentifier(seen map[string]map[string]string, kind, id, owner string) error {
	if err := validIdentifier(kind, id); err != nil {
		return err
	}
	if previous, exists := seen[kind][id]; exists {
		return fmt.Errorf("runtime registry: duplicate %s %q in %q and %q", kind, id, previous, owner)
	}
	seen[kind][id] = owner
	return nil
}

func validIdentifier(kind, id string) error {
	if id == "" || strings.TrimSpace(id) != id || strings.ContainsRune(id, '\x00') {
		return fmt.Errorf("runtime registry: invalid %s identifier %q", kind, id)
	}
	return nil
}

func cloneDefinition(in ProfileDefinition) ProfileDefinition {
	out := ProfileDefinition{
		ID:     in.ID,
		Routes: append([]Route(nil), in.Routes...),
	}
	out.Modules = make([]ModuleDefinition, len(in.Modules))
	for i, module := range in.Modules {
		out.Modules[i] = ModuleDefinition{
			ID:        module.ID,
			Programs:  append([]string(nil), module.Programs...),
			Policies:  append([]string(nil), module.Policies...),
			Stores:    append([]string(nil), module.Stores...),
			KeyScopes: append([]string(nil), module.KeyScopes...),
		}
	}
	return out
}

package runtime

import (
	"reflect"
	"strings"
	"testing"
)

func testDefinition(suffix string) ProfileDefinition {
	return ProfileDefinition{
		ID: "profile-" + suffix,
		Modules: []ModuleDefinition{{
			ID: "module-" + suffix, Programs: []string{"program-" + suffix},
			Policies: []string{"policy-" + suffix}, Stores: []string{"store-" + suffix},
			KeyScopes: []string{"key-" + suffix},
		}},
		Routes: []Route{{Method: "POST", Path: "/v1/" + suffix}},
	}
}

func TestCompileRegistryRejectsDuplicateIdentifiers(t *testing.T) {
	tests := []struct {
		name   string
		kind   string
		mutate func(*ProfileDefinition, ProfileDefinition)
	}{
		{"profile", "profile", func(right *ProfileDefinition, left ProfileDefinition) { right.ID = left.ID }},
		{"module", "module", func(right *ProfileDefinition, left ProfileDefinition) { right.Modules[0].ID = left.Modules[0].ID }},
		{"program", "program", func(right *ProfileDefinition, left ProfileDefinition) {
			right.Modules[0].Programs[0] = left.Modules[0].Programs[0]
		}},
		{"policy", "policy", func(right *ProfileDefinition, left ProfileDefinition) {
			right.Modules[0].Policies[0] = left.Modules[0].Policies[0]
		}},
		{"store", "store", func(right *ProfileDefinition, left ProfileDefinition) {
			right.Modules[0].Stores[0] = left.Modules[0].Stores[0]
		}},
		{"key scope", "key scope", func(right *ProfileDefinition, left ProfileDefinition) {
			right.Modules[0].KeyScopes[0] = left.Modules[0].KeyScopes[0]
		}},
		{"route", "route", func(right *ProfileDefinition, left ProfileDefinition) { right.Routes[0] = left.Routes[0] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left, right := testDefinition("left"), testDefinition("right")
			test.mutate(&right, left)
			if _, err := Compile(left, right); err == nil || !strings.Contains(err.Error(), "duplicate "+test.kind) {
				t.Fatalf("duplicate %s = %v", test.kind, err)
			}
		})
	}
}

func TestCompiledRegistryIsImmutable(t *testing.T) {
	definition := testDefinition("one")
	registry, err := Compile(definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.ID = "mutated"
	definition.Modules[0].Programs[0] = "mutated"
	definition.Routes[0].Path = "/mutated"

	profile, ok := registry.Profile("profile-one")
	if !ok || profile.ID() != "profile-one" {
		t.Fatalf("compiled profile = %q, %v", profile.ID(), ok)
	}
	modules := profile.Modules()
	routes := profile.Routes()
	if modules[0].Programs[0] != "program-one" || routes[0].Path != "/v1/one" {
		t.Fatalf("source mutation changed registry: %+v %+v", modules, routes)
	}
	modules[0].Programs[0] = "caller-mutated"
	routes[0].Path = "/caller-mutated"
	again, _ := registry.Profile("profile-one")
	if reflect.DeepEqual(again.Modules(), modules) || reflect.DeepEqual(again.Routes(), routes) {
		t.Fatal("registry exposed mutable profile slices")
	}
}

func TestCompileRegistryRejectsInvalidOrEmptyDefinitions(t *testing.T) {
	if _, err := Compile(); err == nil {
		t.Fatal("empty registry accepted")
	}
	for _, mutate := range []func(*ProfileDefinition){
		func(d *ProfileDefinition) { d.ID = " profile" },
		func(d *ProfileDefinition) { d.Modules = nil },
		func(d *ProfileDefinition) { d.Modules[0].Programs = nil; d.Modules[0].Policies = nil },
		func(d *ProfileDefinition) { d.Routes = nil },
		func(d *ProfileDefinition) { d.Routes[0].Method = "post" },
		func(d *ProfileDefinition) { d.Routes[0].Path = "v1/no-leading-slash" },
	} {
		definition := testDefinition("invalid")
		mutate(&definition)
		if _, err := Compile(definition); err == nil {
			t.Fatalf("invalid definition accepted: %+v", definition)
		}
	}
}

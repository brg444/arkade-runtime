package application_test

import (
	"reflect"
	"testing"

	"github.com/brg444/vaulted-guardian/internal/application"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestKeyCapabilitiesExposeNoSigningOrRawKeyOperation(t *testing.T) {
	value := reflect.TypeOf(application.KeyCapabilities{})
	pointer := reflect.PointerTo(value)
	if got, want := exportedMethods(value), []string{"Validate"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("key capability value methods = %v, want %v", got, want)
	}
	if got, want := exportedMethods(pointer), []string{"Validate", "Wipe"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("key capability pointer methods = %v, want %v", got, want)
	}

	privateKeyType := reflect.TypeOf((*btcec.PrivateKey)(nil))
	genericSignerType := reflect.TypeOf((*application.Signer)(nil)).Elem()
	for _, surface := range []reflect.Type{reflect.TypeOf(application.Service{}), reflect.TypeOf(application.Deps{})} {
		for i := 0; i < surface.NumField(); i++ {
			field := surface.Field(i)
			if field.IsExported() && (field.Type == privateKeyType || field.Type == genericSignerType) {
				t.Fatalf("%s exports raw or generic signing field %q", surface.Name(), field.Name)
			}
		}
	}
}

func exportedMethods(typ reflect.Type) []string {
	out := make([]string, typ.NumMethod())
	for i := range out {
		out[i] = typ.Method(i).Name
	}
	return out
}

// runtime-state is an offline operator tool for Arkade Runtime restore units.
// It must never run alongside the authorizer process against the same files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/brg444/arkade-vault-server/internal/operations"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "snapshot":
		err = runSnapshot(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "restore":
		err = runRestore(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime-state: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: runtime-state <snapshot|verify|restore> [flags]")
}

func runSnapshot(args []string) error {
	flags := newFlagSet("snapshot")
	database := flags.String("db", "", "absolute stopped Runtime SQLite path")
	sequence := flags.String("policy-sequence", "", "absolute stopped Runtime policy-sequence path")
	keyFile := flags.String("vault-cosigner-key-file", "", "protected VaultCosigner scalar file")
	output := flags.String("output", "", "new private state-unit directory")
	commit := flags.String("source-commit", "", "full audited Runtime source commit")
	image := flags.String("image-digest", "", "audited Runtime image digest")
	stopped := flags.Bool("service-stopped", false, "acknowledge that traffic is drained and the Runtime is stopped")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("snapshot accepts flags only")
	}
	manifest, err := operations.Snapshot(operations.SnapshotConfig{
		DatabasePath:         *database,
		PolicySequencePath:   *sequence,
		VaultCosignerKeyFile: *keyFile,
		OutputDirectory:      *output,
		SourceCommit:         *commit,
		ImageDigest:          *image,
		ServiceStopped:       *stopped,
	})
	if err != nil {
		return err
	}
	return writeResult(manifest)
}

func runVerify(args []string) error {
	flags := newFlagSet("verify")
	unit := flags.String("unit", "", "absolute private state-unit directory")
	keyFile := flags.String("vault-cosigner-key-file", "", "protected VaultCosigner scalar file")
	commit := flags.String("expected-source-commit", "", "required full Runtime source commit")
	image := flags.String("expected-image-digest", "", "required Runtime image digest")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("verify accepts flags only")
	}
	manifest, err := operations.Verify(operations.VerifyConfig{
		UnitDirectory:        *unit,
		VaultCosignerKeyFile: *keyFile,
		ExpectedCommit:       *commit,
		ExpectedImageDigest:  *image,
	})
	if err != nil {
		return err
	}
	return writeResult(manifest)
}

func runRestore(args []string) error {
	flags := newFlagSet("restore")
	unit := flags.String("unit", "", "absolute private state-unit directory")
	database := flags.String("db", "", "absolute stopped Runtime SQLite path")
	sequence := flags.String("policy-sequence", "", "absolute stopped Runtime policy-sequence path")
	keyFile := flags.String("vault-cosigner-key-file", "", "protected VaultCosigner scalar file")
	commit := flags.String("expected-source-commit", "", "required full Runtime source commit")
	image := flags.String("expected-image-digest", "", "required Runtime image digest")
	stopped := flags.Bool("service-stopped", false, "acknowledge that traffic is drained and the Runtime is stopped")
	replace := flags.Bool("replace", false, "acknowledge replacement of both state artifacts")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("restore accepts flags only")
	}
	manifest, err := operations.Restore(operations.RestoreConfig{
		UnitDirectory:        *unit,
		VaultCosignerKeyFile: *keyFile,
		DatabasePath:         *database,
		PolicySequencePath:   *sequence,
		ExpectedCommit:       *commit,
		ExpectedImageDigest:  *image,
		ServiceStopped:       *stopped,
		Replace:              *replace,
	})
	if err != nil {
		return err
	}
	return writeResult(manifest)
}

func newFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	return flags
}

func writeResult(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

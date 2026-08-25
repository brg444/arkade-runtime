// Package operations provides offline-only Arkade Runtime state-unit tooling.
// It has no HTTP surface and never exposes signing or key material.
package operations

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"time"

	"github.com/brg444/arkade-vault-server/internal/authorizer"
	"github.com/brg444/arkade-vault-server/internal/contractpack"
	"github.com/brg444/arkade-vault-server/internal/policy"
)

const (
	StateUnitFormat   = "arkade-runtime-state-unit/v1"
	DatabaseFileName  = "vault.sqlite"
	SequenceFileName  = "policy-sequence"
	ManifestFileName  = "manifest.json"
	maxManifestBytes  = 64 * 1024
	stateArtifactMode = 0o600
)

var (
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Artifact binds one fixed-name state artifact to exact bytes.
type Artifact struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest binds one coherent database/sequence decision to the exact Runtime
// source and image qualified by the operator.
type Manifest struct {
	Format             string                     `json:"format"`
	CreatedAt          string                     `json:"createdAt"`
	SourceCommit       string                     `json:"sourceCommit"`
	ImageDigest        string                     `json:"imageDigest"`
	ContractPackSHA256 string                     `json:"contractPackSha256"`
	State              policy.RestoreStateSummary `json:"state"`
	Database           Artifact                   `json:"database"`
	PolicySequence     Artifact                   `json:"policySequence"`
}

type SnapshotConfig struct {
	DatabasePath         string
	PolicySequencePath   string
	VaultCosignerKeyFile string
	OutputDirectory      string
	SourceCommit         string
	ImageDigest          string
	ServiceStopped       bool
	Now                  func() time.Time
}

type VerifyConfig struct {
	UnitDirectory        string
	VaultCosignerKeyFile string
	ExpectedCommit       string
	ExpectedImageDigest  string
}

type RestoreConfig struct {
	UnitDirectory        string
	VaultCosignerKeyFile string
	DatabasePath         string
	PolicySequencePath   string
	ExpectedCommit       string
	ExpectedImageDigest  string
	ServiceStopped       bool
	Replace              bool
}

// Snapshot creates a new immutable-by-convention restore directory. The
// caller must first stop the Runtime and drain traffic; the explicit flag is a
// guard against treating a file copy as an online backup protocol.
func Snapshot(cfg SnapshotConfig) (Manifest, error) {
	var manifest Manifest
	if !cfg.ServiceStopped {
		return manifest, fmt.Errorf("snapshot requires an explicit service-stopped acknowledgement")
	}
	if err := validateStatePaths(cfg.DatabasePath, cfg.PolicySequencePath); err != nil {
		return manifest, err
	}
	cfg.DatabasePath, _ = cleanAbsolutePath("database path", cfg.DatabasePath)
	cfg.PolicySequencePath, _ = cleanAbsolutePath("policy-sequence path", cfg.PolicySequencePath)
	if err := validateReleaseIdentity(cfg.SourceCommit, cfg.ImageDigest); err != nil {
		return manifest, err
	}
	if err := contractpack.Validate(); err != nil {
		return manifest, fmt.Errorf("release Contract Pack: %w", err)
	}
	if err := requirePrivateRegularFile(cfg.VaultCosignerKeyFile); err != nil {
		return manifest, fmt.Errorf("VaultCosigner key file: %w", err)
	}
	output, err := cleanAbsolutePath("snapshot output directory", cfg.OutputDirectory)
	if err != nil {
		return manifest, err
	}
	if _, err := os.Lstat(output); err == nil {
		return manifest, fmt.Errorf("snapshot output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return manifest, fmt.Errorf("inspect snapshot output: %w", err)
	}
	if err := requirePrivateDirectory(filepath.Dir(output)); err != nil {
		return manifest, fmt.Errorf("snapshot parent: %w", err)
	}
	if err := requireNoSQLiteSidecars(cfg.DatabasePath); err != nil {
		return manifest, err
	}
	before, err := authorizer.VerifyRestoreState(cfg.DatabasePath, cfg.PolicySequencePath, cfg.VaultCosignerKeyFile)
	if err != nil {
		return manifest, fmt.Errorf("verify source state: %w", err)
	}

	temporary, err := os.MkdirTemp(filepath.Dir(output), "."+filepath.Base(output)+".tmp-")
	if err != nil {
		return manifest, fmt.Errorf("create snapshot staging directory: %w", err)
	}
	if err := os.Chmod(temporary, 0o700); err != nil {
		_ = os.RemoveAll(temporary)
		return manifest, fmt.Errorf("protect snapshot staging directory: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(temporary)
		}
	}()
	databaseArtifact, err := copyArtifact(cfg.DatabasePath, filepath.Join(temporary, DatabaseFileName), DatabaseFileName)
	if err != nil {
		return manifest, err
	}
	sequenceArtifact, err := copyArtifact(cfg.PolicySequencePath, filepath.Join(temporary, SequenceFileName), SequenceFileName)
	if err != nil {
		return manifest, err
	}
	if err := requireNoSQLiteSidecars(cfg.DatabasePath); err != nil {
		return manifest, err
	}
	after, err := authorizer.VerifyRestoreState(
		filepath.Join(temporary, DatabaseFileName),
		filepath.Join(temporary, SequenceFileName),
		cfg.VaultCosignerKeyFile,
	)
	if err != nil {
		return manifest, fmt.Errorf("verify copied state: %w", err)
	}
	if !reflect.DeepEqual(before, after) {
		return manifest, fmt.Errorf("source state changed while the restore unit was captured")
	}
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	manifest = Manifest{
		Format:             StateUnitFormat,
		CreatedAt:          now().UTC().Format(time.RFC3339Nano),
		SourceCommit:       cfg.SourceCommit,
		ImageDigest:        cfg.ImageDigest,
		ContractPackSHA256: contractpack.SHA256,
		State:              after,
		Database:           databaseArtifact,
		PolicySequence:     sequenceArtifact,
	}
	if err := writeManifest(filepath.Join(temporary, ManifestFileName), manifest); err != nil {
		return Manifest{}, err
	}
	if err := syncDirectory(temporary); err != nil {
		return Manifest{}, err
	}
	if err := os.Rename(temporary, output); err != nil {
		return Manifest{}, fmt.Errorf("publish snapshot: %w", err)
	}
	if err := syncDirectory(filepath.Dir(output)); err != nil {
		return Manifest{}, err
	}
	complete = true
	return manifest, nil
}

// Verify authenticates the manifest, artifact bytes, exact database schema,
// every MAC-protected row, and the independent policy-sequence count and MAC.
func Verify(cfg VerifyConfig) (Manifest, error) {
	var manifest Manifest
	unit, err := cleanAbsolutePath("state-unit directory", cfg.UnitDirectory)
	if err != nil {
		return manifest, err
	}
	if err := requirePrivateDirectory(unit); err != nil {
		return manifest, fmt.Errorf("state-unit directory: %w", err)
	}
	if err := requirePrivateRegularFile(cfg.VaultCosignerKeyFile); err != nil {
		return manifest, fmt.Errorf("VaultCosigner key file: %w", err)
	}
	if err := requireStateUnitContents(unit); err != nil {
		return manifest, err
	}
	if err := contractpack.Validate(); err != nil {
		return manifest, fmt.Errorf("release Contract Pack: %w", err)
	}
	manifest, err = readManifest(filepath.Join(unit, ManifestFileName))
	if err != nil {
		return Manifest{}, err
	}
	if err := validateManifest(manifest, cfg.ExpectedCommit, cfg.ExpectedImageDigest); err != nil {
		return Manifest{}, err
	}
	if err := verifyArtifact(filepath.Join(unit, DatabaseFileName), manifest.Database, DatabaseFileName); err != nil {
		return Manifest{}, err
	}
	if err := verifyArtifact(filepath.Join(unit, SequenceFileName), manifest.PolicySequence, SequenceFileName); err != nil {
		return Manifest{}, err
	}
	state, err := authorizer.VerifyRestoreState(
		filepath.Join(unit, DatabaseFileName),
		filepath.Join(unit, SequenceFileName),
		cfg.VaultCosignerKeyFile,
	)
	if err != nil {
		return Manifest{}, fmt.Errorf("verify state unit: %w", err)
	}
	if !reflect.DeepEqual(state, manifest.State) {
		return Manifest{}, fmt.Errorf("state-unit summary does not match authenticated artifacts")
	}
	return manifest, nil
}

// Restore replaces both stopped Runtime state artifacts from one verified
// unit. It stages both files before replacement and rolls the first rename
// back if the second or the final authenticated verification fails.
func Restore(cfg RestoreConfig) (Manifest, error) {
	var manifest Manifest
	if !cfg.ServiceStopped {
		return manifest, fmt.Errorf("restore requires an explicit service-stopped acknowledgement")
	}
	if !cfg.Replace {
		return manifest, fmt.Errorf("restore requires an explicit replace acknowledgement")
	}
	if err := validateReleaseIdentity(cfg.ExpectedCommit, cfg.ExpectedImageDigest); err != nil {
		return manifest, fmt.Errorf("restore expected release: %w", err)
	}
	if err := validateStatePaths(cfg.DatabasePath, cfg.PolicySequencePath); err != nil {
		return manifest, err
	}
	cfg.DatabasePath, _ = cleanAbsolutePath("database path", cfg.DatabasePath)
	cfg.PolicySequencePath, _ = cleanAbsolutePath("policy-sequence path", cfg.PolicySequencePath)
	cfg.UnitDirectory, _ = cleanAbsolutePath("state-unit directory", cfg.UnitDirectory)
	manifest, err := Verify(VerifyConfig{
		UnitDirectory:        cfg.UnitDirectory,
		VaultCosignerKeyFile: cfg.VaultCosignerKeyFile,
		ExpectedCommit:       cfg.ExpectedCommit,
		ExpectedImageDigest:  cfg.ExpectedImageDigest,
	})
	if err != nil {
		return Manifest{}, err
	}
	if err := requirePrivateDirectory(filepath.Dir(cfg.DatabasePath)); err != nil {
		return Manifest{}, fmt.Errorf("database directory: %w", err)
	}
	if err := requirePrivateDirectory(filepath.Dir(cfg.PolicySequencePath)); err != nil {
		return Manifest{}, fmt.Errorf("policy-sequence directory: %w", err)
	}
	if err := rejectSymlinkTarget(cfg.DatabasePath); err != nil {
		return Manifest{}, err
	}
	if err := rejectSymlinkTarget(cfg.PolicySequencePath); err != nil {
		return Manifest{}, err
	}
	nonce, err := randomSuffix()
	if err != nil {
		return Manifest{}, err
	}
	databaseStage := cfg.DatabasePath + ".runtime-state-stage-" + nonce
	sequenceStage := cfg.PolicySequencePath + ".runtime-state-stage-" + nonce
	staged := []string{databaseStage, sequenceStage}
	defer func() {
		for _, path := range staged {
			_ = os.Remove(path)
		}
	}()
	if _, err := copyArtifact(filepath.Join(cfg.UnitDirectory, DatabaseFileName), databaseStage, DatabaseFileName); err != nil {
		return Manifest{}, err
	}
	if _, err := copyArtifact(filepath.Join(cfg.UnitDirectory, SequenceFileName), sequenceStage, SequenceFileName); err != nil {
		return Manifest{}, err
	}

	databaseBackup := cfg.DatabasePath + ".runtime-state-backup-" + nonce
	sequenceBackup := cfg.PolicySequencePath + ".runtime-state-backup-" + nonce
	databaseHadOld, err := moveAside(cfg.DatabasePath, databaseBackup)
	if err != nil {
		return Manifest{}, err
	}
	sequenceHadOld, err := moveAside(cfg.PolicySequencePath, sequenceBackup)
	if err != nil {
		if databaseHadOld {
			_ = os.Rename(databaseBackup, cfg.DatabasePath)
		}
		return Manifest{}, err
	}
	rollback := func() {
		_ = os.Remove(cfg.DatabasePath)
		_ = os.Remove(cfg.PolicySequencePath)
		if databaseHadOld {
			_ = os.Rename(databaseBackup, cfg.DatabasePath)
		}
		if sequenceHadOld {
			_ = os.Rename(sequenceBackup, cfg.PolicySequencePath)
		}
	}
	if err := os.Rename(databaseStage, cfg.DatabasePath); err != nil {
		rollback()
		return Manifest{}, fmt.Errorf("install restored database: %w", err)
	}
	staged[0] = ""
	if err := os.Rename(sequenceStage, cfg.PolicySequencePath); err != nil {
		rollback()
		return Manifest{}, fmt.Errorf("install restored policy sequence: %w", err)
	}
	staged[1] = ""
	if _, err := authorizer.VerifyRestoreState(cfg.DatabasePath, cfg.PolicySequencePath, cfg.VaultCosignerKeyFile); err != nil {
		rollback()
		return Manifest{}, fmt.Errorf("verify installed restore unit: %w", err)
	}
	if databaseHadOld {
		if err := os.Remove(databaseBackup); err != nil {
			return Manifest{}, fmt.Errorf("remove prior database after verified restore: %w", err)
		}
	}
	if sequenceHadOld {
		if err := os.Remove(sequenceBackup); err != nil {
			return Manifest{}, fmt.Errorf("remove prior policy sequence after verified restore: %w", err)
		}
	}
	for _, dir := range uniqueSorted([]string{filepath.Dir(cfg.DatabasePath), filepath.Dir(cfg.PolicySequencePath)}) {
		if err := syncDirectory(dir); err != nil {
			return Manifest{}, err
		}
	}
	return manifest, nil
}

func validateStatePaths(databasePath, sequencePath string) error {
	database, err := cleanAbsolutePath("database path", databasePath)
	if err != nil {
		return err
	}
	sequence, err := cleanAbsolutePath("policy-sequence path", sequencePath)
	if err != nil {
		return err
	}
	if database == sequence {
		return fmt.Errorf("database and policy sequence must be distinct files")
	}
	return nil
}

func cleanAbsolutePath(label, path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must be absolute", label)
	}
	clean := filepath.Clean(path)
	if clean == string(filepath.Separator) {
		return "", fmt.Errorf("%s cannot be the filesystem root", label)
	}
	return clean, nil
}

func validateReleaseIdentity(commit, digest string) error {
	if !commitPattern.MatchString(commit) {
		return fmt.Errorf("source commit must be a full lowercase Git SHA-1")
	}
	if !digestPattern.MatchString(digest) {
		return fmt.Errorf("image digest must be sha256:<64 lowercase hex>")
	}
	return nil
}

func validateManifest(manifest Manifest, expectedCommit, expectedDigest string) error {
	if manifest.Format != StateUnitFormat {
		return fmt.Errorf("unsupported state-unit format")
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt); err != nil {
		return fmt.Errorf("state-unit createdAt: %w", err)
	}
	if err := validateReleaseIdentity(manifest.SourceCommit, manifest.ImageDigest); err != nil {
		return err
	}
	if manifest.ContractPackSHA256 != contractpack.SHA256 {
		return fmt.Errorf("state-unit Contract Pack digest does not match this release")
	}
	if expectedCommit != "" && manifest.SourceCommit != expectedCommit {
		return fmt.Errorf("state-unit source commit does not match the expected release")
	}
	if expectedDigest != "" && manifest.ImageDigest != expectedDigest {
		return fmt.Errorf("state-unit image digest does not match the expected release")
	}
	if manifest.State.EconomicOutflowCount != manifest.State.PolicySequenceCount {
		return fmt.Errorf("state-unit manifest has mismatched policy counts")
	}
	return nil
}

func writeManifest(path string, manifest Manifest) error {
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state-unit manifest: %w", err)
	}
	raw = append(raw, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, stateArtifactMode)
	if err != nil {
		return fmt.Errorf("create state-unit manifest: %w", err)
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return fmt.Errorf("write state-unit manifest: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync state-unit manifest: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close state-unit manifest: %w", err)
	}
	return nil
}

func readManifest(path string) (Manifest, error) {
	var manifest Manifest
	file, err := os.Open(path)
	if err != nil {
		return manifest, fmt.Errorf("open state-unit manifest: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxManifestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode state-unit manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Manifest{}, fmt.Errorf("state-unit manifest must contain one JSON object")
	}
	return manifest, nil
}

func copyArtifact(source, destination, name string) (Artifact, error) {
	var artifact Artifact
	if err := requirePrivateRegularFile(source); err != nil {
		return artifact, fmt.Errorf("source %s: %w", name, err)
	}
	in, err := os.Open(source)
	if err != nil {
		return artifact, fmt.Errorf("open source %s: %w", name, err)
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, stateArtifactMode)
	if err != nil {
		return artifact, fmt.Errorf("create copied %s: %w", name, err)
	}
	hash := sha256.New()
	written, copyErr := io.CopyBuffer(io.MultiWriter(out, hash), bufio.NewReader(in), make([]byte, 128*1024))
	if copyErr == nil {
		copyErr = out.Sync()
	}
	closeErr := out.Close()
	if copyErr != nil {
		return artifact, fmt.Errorf("copy %s: %w", name, copyErr)
	}
	if closeErr != nil {
		return artifact, fmt.Errorf("close copied %s: %w", name, closeErr)
	}
	return Artifact{Name: name, Size: written, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func verifyArtifact(path string, artifact Artifact, expectedName string) error {
	if artifact.Name != expectedName || artifact.Size < 0 || !sha256Pattern.MatchString(artifact.SHA256) {
		return fmt.Errorf("invalid %s manifest entry", expectedName)
	}
	if err := requirePrivateRegularFile(path); err != nil {
		return fmt.Errorf("state-unit %s: %w", expectedName, err)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open state-unit %s: %w", expectedName, err)
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("hash state-unit %s: %w", expectedName, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close state-unit %s: %w", expectedName, closeErr)
	}
	if size != artifact.Size || !bytes.Equal([]byte(hex.EncodeToString(hash.Sum(nil))), []byte(artifact.SHA256)) {
		return fmt.Errorf("state-unit %s digest or size mismatch", expectedName)
	}
	return nil
}

func requirePrivateRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("must not grant group or world permissions")
	}
	return nil
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("must be a non-symlink directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("must not grant group or world permissions")
	}
	return nil
}

func rejectSymlinkTarget(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect restore target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("restore target must be a regular non-symlink file")
	}
	return nil
}

func requireNoSQLiteSidecars(databasePath string) error {
	for _, suffix := range []string{"-journal", "-shm", "-wal"} {
		if _, err := os.Lstat(databasePath + suffix); err == nil {
			return fmt.Errorf("SQLite sidecar %s exists; stop the Runtime cleanly before snapshot", suffix)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect SQLite sidecar %s: %w", suffix, err)
		}
	}
	return nil
}

func requireStateUnitContents(unit string) error {
	entries, err := os.ReadDir(unit)
	if err != nil {
		return fmt.Errorf("read state-unit directory: %w", err)
	}
	want := map[string]struct{}{
		DatabaseFileName: {},
		SequenceFileName: {},
		ManifestFileName: {},
	}
	if len(entries) != len(want) {
		return fmt.Errorf("state-unit directory must contain exactly the manifest, database, and policy sequence")
	}
	for _, entry := range entries {
		if _, ok := want[entry.Name()]; !ok || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("state-unit directory contains an unexpected entry")
		}
	}
	return nil
}

func moveAside(path, backup string) (bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("inspect restore target: %w", err)
	}
	if err := os.Rename(path, backup); err != nil {
		return false, fmt.Errorf("stage prior restore target: %w", err)
	}
	return true, nil
}

func randomSuffix() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("restore transaction id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func uniqueSorted(paths []string) []string {
	set := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path != "" {
			set[path] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for path := range set {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

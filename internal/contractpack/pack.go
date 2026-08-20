// Package contractpack embeds the named-program pack. Production loads this
// byte slice at startup; it is not a process-relative file path.
package contractpack

import _ "embed"

// JSON is the exact contract-pack.json committed at the repo root.
//
//go:embed contract-pack.json
var JSON []byte

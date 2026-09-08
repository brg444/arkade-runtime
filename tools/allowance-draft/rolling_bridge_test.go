package allowancedraft

import "github.com/brg444/arkade-runtime/internal/vault/rolling"

type RollingParameters = rolling.RollingParameters
type RollingScripts = rolling.RollingScripts
type RollingState = rolling.RollingState
type Debit = rolling.Debit
type HistoryProof = rolling.HistoryProof
type FinalizationReceipt = rolling.FinalizationReceipt

const (
	RollingProgram   = rolling.RollingProgram
	RollingStateSize = rolling.RollingStateSize
	DebitSize        = rolling.DebitSize
	HistoryDepth     = rolling.HistoryDepth
	WindowSeconds    = rolling.WindowSeconds
	ReceiptSize      = rolling.ReceiptSize
)

var (
	CompileRolling      = rolling.Compile
	InitialRollingState = rolling.InitialRollingState
	DecodeRollingState  = rolling.DecodeRollingState
	DecodeDebit         = rolling.DecodeDebit
	BuildHistoryProof   = rolling.BuildHistoryProof
	ApplyDebit          = rolling.ApplyDebit
	ApplyCredit         = rolling.ApplyCredit
	emptyRoots          = rolling.EmptyRoots
)

// Package apperr is the application error set. HTTP maps Code, never
// substring-matches err.Error().
package apperr

import "errors"

type Code string

const (
	CodeRejected         Code = "REJECTED"
	CodeNotFound         Code = "NOT_FOUND"
	CodeBusy             Code = "BUSY"
	CodeVaultIDRequired  Code = "VAULT_ID_REQUIRED"
	CodeNotEnrolled      Code = "NOT_ENROLLED"
	CodeEnrollmentClosed Code = "ENROLLMENT_CLOSED"
)

type Error struct {
	Code Code
	Msg  string
}

func (e *Error) Error() string {
	if e == nil {
		return "rejected"
	}
	if e.Msg != "" {
		return e.Msg
	}
	return string(e.Code)
}

func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && e != nil && t != nil && e.Code == t.Code
}

func New(code Code, msg string) *Error {
	return &Error{Code: code, Msg: msg}
}

func Of(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return New(CodeRejected, err.Error())
}

var (
	ErrRejected         = New(CodeRejected, "request rejected")
	ErrNotFound         = New(CodeNotFound, "not found")
	ErrBusy             = New(CodeBusy, "busy")
	ErrVaultIDRequired  = New(CodeVaultIDRequired, "vault id required")
	ErrNotEnrolled      = New(CodeNotEnrolled, "not enrolled")
	ErrEnrollmentClosed = New(CodeEnrollmentClosed, "not found")
)

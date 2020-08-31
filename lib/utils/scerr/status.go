package scerr

import "fmt"

// ErrorLike interface
type ErrorLike interface {
    IsError() bool
}

// func iserror(err error) bool {
// 	if err == nil {
// 		return false
// 	}
// 	ei, ok := err.(ErrorLike)
// 	if !ok {
// 		return true
// 	}
// 	return ei.IsError()
// }

// Status interface
type Status interface {
    Message() string
    Cause() error
    IsError() bool
}

type status struct {
    success bool
    message string
    cause   error
}

// WrapErr ...
func WrapErr(err error, msg string) Status {
    return &status{
        success: false,
        message: msg,
        cause:   err,
    }
}

// Success ..
func Success(msg string, args ...interface{}) Status {
    return &status{
        success: true,
        message: fmt.Sprintf(msg, args...),
    }
}

// Message ...
func (stat *status) Message() string {
    return stat.message
}

// Cause ...
func (stat *status) Cause() error {
    return stat.cause
}

// IsError ...
func (stat *status) IsError() bool {
    return stat.cause != nil || !stat.success
}

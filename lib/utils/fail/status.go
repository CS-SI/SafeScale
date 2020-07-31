package fail

import "fmt"

// ErrorLike interface
type ErrorLike interface {
    IsError() bool
}

// IsError ...
func IsError(err error) bool {
    if err == nil {
        return false
    }
    ei, ok := err.(ErrorLike)
    if !ok {
        return true
    }
    return ei.IsError()
}

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

// StatusWrapErr ...
func StatusWrapErr(err error, msg string) Status {
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
func (msg *status) Message() string {
    return msg.message
}

// Cause ...
func (msg *status) Cause() error {
    return msg.cause
}

// IsError ...
func (msg *status) IsError() bool {
    return msg.cause != nil || !msg.success
}

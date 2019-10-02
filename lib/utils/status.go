package utils

import "fmt"

type ErrorLike interface {
	IsError() bool
}

func iserror(err error) bool {
	if err == nil {
		return false
	}
	ei, ok := err.(ErrorLike)
	if !ok {
		return true
	}
	return ei.IsError()
}

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

func WrapErr(err error, msg string) Status {
	return &status{
		success: false,
		message: msg,
		cause:   err,
	}
}

func Success(msg string, args ...interface{}) Status {
	return &status{
		success: true,
		message: fmt.Sprintf(msg, args...),
	}
}

func (me *status) Message() string {
	return me.message
}

func (me *status) Cause() error {
	return me.cause
}

func (me *status) IsError() bool {
	return me.cause != nil || !me.success
}

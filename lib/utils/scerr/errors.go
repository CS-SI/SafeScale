/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package scerr

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

var removePart atomic.Value

// AddConsequence adds an error 'err' to the list of consequences
func AddConsequence(err error, cons error) error {
	type consequencer interface {
		Consequences() []error
		AddConsequence(error) error
		Error() string
	}

	if err != nil {
		conseq, ok := err.(consequencer)
		if ok {
			if cons != nil {
				nerr := conseq.AddConsequence(cons)
				return nerr
			}
			return conseq
		}
		logrus.Errorf("trying to add error [%s] to existing error [%s] but failed", cons, err)
	}
	return err
}

// Consequences returns the list of consequences
func Consequences(err error) []error {
	type consequencer interface {
		Consequences() []error
		AddConsequence(error) error
		Error() string
	}

	if err != nil {
		conseq, ok := err.(consequencer)
		if ok {
			return conseq.Consequences()
		}
	}

	return []error{}
}

// DecorateError changes the error to something more comprehensible when
// timeout occurred
func DecorateError(err error, action string, timeout time.Duration) error {
	if IsGRPCTimeout(err) {
		if timeout > 0 {
			return fmt.Errorf("%s took too long (> %v) to respond", action, timeout)
		}
		return fmt.Errorf("%s took too long to respond", action)
	}
	msg := err.Error()
	if strings.Contains(msg, "desc = ") {
		pos := strings.Index(msg, "desc = ") + 7
		msg = msg[pos:]

		if strings.Index(msg, " :") == 0 {
			msg = msg[2:]
		}
		return fmt.Errorf(msg)
	}
	return err
}

// IsGRPCTimeout tells if the err is a timeout kind
func IsGRPCTimeout(err error) bool {
	return grpcstatus.Code(err) == codes.DeadlineExceeded
}

// ErrCore ...
type ErrCore struct {
	Message      string
	cause        error
	consequences []error
}

// CauseFormatter generates a string containing information about the causing error and the derived errors while trying to clean up
func (e ErrCore) CauseFormatter() string {
	msgFinal := ""

	if e.Cause() != nil {
		msgFinal += " ["
		msgFinal += "caused by {"
		msgFinal += e.Cause().Error()
		msgFinal += "}]"
	}

	lenConseq := len(e.Consequences())
	if lenConseq > 0 {
		msgFinal += "[with consequences {"
		for ind, con := range e.Consequences() {
			msgFinal += con.Error()
			if ind+1 < lenConseq {
				msgFinal += ";"
			}
		}
		msgFinal += "}]"
	}

	return msgFinal
}

// Reset imports content of error err to receiving error e
func (e ErrCore) Reset(err error) ErrCore {
	if err != nil {
		if cerr, ok := err.(ErrCore); ok {
			e.Message = cerr.Message
			e.consequences = cerr.consequences
			e.cause = cerr.cause
		}
	}
	return e
}

// Cause returns an error's cause
func (e ErrCore) Cause() error {
	return e.cause
}

// Consequences returns the consequences of current error (detected teardown problems)
func (e ErrCore) Consequences() []error {
	return e.consequences
}

// Wrap creates a new error with a message 'message' and a cause error 'cause'
func Wrap(cause error, message string) ErrCore {
	return NewErrCore(message, cause, []error{})
}

// NewErrCore creates a new error with a message 'message', a cause error 'cause' and a list of teardown problems 'consequences'
func NewErrCore(message string, cause error, consequences []error) ErrCore {
	if consequences == nil {
		return ErrCore{
			Message:      message,
			cause:        cause,
			consequences: []error{},
		}
	}

	return ErrCore{
		Message:      message,
		cause:        cause,
		consequences: consequences,
	}
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrCore) AddConsequence(err error) error {
	if err != nil {
		if e.consequences == nil {
			e.consequences = []error{}
		}
		e.consequences = append(e.consequences, err)
	}
	return e
}

// Error returns a human-friendly error explanation
func (e ErrCore) Error() string {
	msgFinal := e.Message

	msgFinal += e.CauseFormatter()

	return msgFinal
}

// Cause returns the cause of an error if it implements the causer interface
func Cause(err error) (resp error) {
	type causer interface {
		Cause() error
	}

	resp = err

	for err != nil {
		cause, ok := err.(causer)
		if !ok {
			break
		}
		err = cause.Cause()
		if err != nil {
			resp = err
		}
	}

	return resp
}

// ErrTimeout defines a Timeout error
type ErrTimeout struct {
	ErrCore
	dur time.Duration
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrTimeout) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// TimeoutError ...
func TimeoutError(msg string, timeout time.Duration, cause error) ErrTimeout {
	return ErrTimeout{
		ErrCore: ErrCore{
			Message:      msg,
			cause:        cause,
			consequences: []error{},
		},
		dur: timeout,
	}
}

// ErrNotFound resource not found error
type ErrNotFound struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrNotFound) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// NotFoundError creates a ErrNotFound error
func NotFoundError(msg string) ErrNotFound {
	return ErrNotFound{
		ErrCore: ErrCore{
			Message:      msg,
			cause:        nil,
			consequences: []error{},
		},
	}
}

// ErrNotAvailable resource not available error
type ErrNotAvailable struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrNotAvailable) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// NotAvailableError creates a NotAvailable error
func NotAvailableError(msg string) ErrNotAvailable {
	return ErrNotAvailable{
		ErrCore: ErrCore{
			Message:      msg,
			cause:        nil,
			consequences: []error{},
		},
	}
}

// ErrDuplicate already exists error
type ErrDuplicate struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrDuplicate) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// DuplicateError creates a ErrDuplicate error
func DuplicateError(msg string) ErrDuplicate {
	return ErrDuplicate{
		ErrCore: ErrCore{
			Message:      msg,
			cause:        nil,
			consequences: []error{},
		},
	}
}

// ErrInvalidRequest ...
type ErrInvalidRequest struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrInvalidRequest) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// InvalidRequestError creates a ErrInvalidRequest error
func InvalidRequestError(msg string) ErrInvalidRequest {
	return ErrInvalidRequest{
		ErrCore: ErrCore{
			Message:      msg,
			cause:        nil,
			consequences: []error{},
		},
	}
}

// ErrAccessDenied ...
type ErrAccessDenied struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrAccessDenied) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// AccessDeniedError creates a ErrAccessDenied error
func AccessDeniedError(msg string) ErrAccessDenied {
	return ErrAccessDenied{
		ErrCore: ErrCore{
			Message:      msg,
			cause:        nil,
			consequences: []error{},
		},
	}
}

// ErrAborted ...
type ErrAborted struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrAborted) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// AbortedError creates a ErrAborted error
func AbortedError() ErrAborted {
	return ErrAborted{
		ErrCore: ErrCore{
			Message:      "aborted",
			cause:        nil,
			consequences: []error{},
		},
	}
}

// ErrOverflow ...
type ErrOverflow struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrOverflow) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// OverflowError creates a ErrOverflow error
func OverflowError(msg string) ErrOverflow {
	return ErrOverflow{
		ErrCore: ErrCore{
			Message:      msg,
			cause:        nil,
			consequences: []error{},
		},
	}
}

// ErrNotImplemented ...
type ErrNotImplemented struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrNotImplemented) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// NotImplementedError creates a ErrNotImplemented error
func NotImplementedError(what string) ErrNotImplemented {
	var msg string
	if pc, file, line, ok := runtime.Caller(1); ok {
		if f := runtime.FuncForPC(pc); f != nil {
			filename := strings.Replace(file, getPartToRemove(), "", 1)
			if len(what) > 0 {
				msg = fmt.Sprintf("not implemented yet: %s : %s [%s:%d]", what, filepath.Base(f.Name()), filename, line)
			} else {
				msg = fmt.Sprintf("not implemented yet: %s [%s:%d]", filepath.Base(f.Name()), filename, line)
			}
		}
	}

	if len(msg) == 0 {
		msg = "not implemented yet!"
		if what != "" {
			msg += ": " + what
		}
	}

	return ErrNotImplemented{
		ErrCore: ErrCore{
			Message:      msg,
			cause:        nil,
			consequences: []error{},
		},
	}
}

// ErrList ...
type ErrList struct {
	ErrCore
	errors []error
}

// ErrListError creates a ErrList
func ErrListError(errors []error) error {
	if len(errors) == 0 {
		return nil
	}

	return ErrList{
		ErrCore: ErrCore{},
		errors:  errors,
	}
}

func (e ErrList) Error() string {
	return spew.Sdump(e.errors)
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrList) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// ErrInvalidInstance ...
type ErrInvalidInstance struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrInvalidInstance) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// InvalidInstanceError creates a ErrInvalidInstance error
func InvalidInstanceError() ErrInvalidInstance {
	var msg string
	if pc, file, line, ok := runtime.Caller(2); ok {
		if f := runtime.FuncForPC(pc); f != nil {
			filename := strings.Replace(file, getPartToRemove(), "", 1)
			msg = fmt.Sprintf("invalid instance: calling %s() from a nil pointer [%s:%d]\n%s", filepath.Base(f.Name()), filename, line, debug.Stack())
		}
	}
	if msg == "" {
		msg = fmt.Sprintf("invalid instance: calling from a nil pointer")
	}

	return ErrInvalidInstance{
		ErrCore: ErrCore{
			Message:      msg,
			cause:        nil,
			consequences: []error{},
		},
	}
}

// ErrInvalidParameter ...
type ErrInvalidParameter struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrInvalidParameter) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// InvalidParameterError creates a ErrInvalidParameter error
func InvalidParameterError(what, why string) ErrInvalidParameter {
	var msg string
	if pc, file, line, ok := runtime.Caller(1); ok {
		if f := runtime.FuncForPC(pc); f != nil {
			filename := strings.Replace(file, getPartToRemove(), "", 1)
			msg = fmt.Sprintf("invalid parameter '%s' in %s: %s [%s:%d]\n%s", what, filepath.Base(f.Name()), why, filename, line, debug.Stack())
		}
	}
	if msg == "" {
		msg = fmt.Sprintf("invalid parameter '%s': %s", what, why)
	}

	return ErrInvalidParameter{
		ErrCore: ErrCore{
			Message:      msg,
			cause:        nil,
			consequences: []error{},
		},
	}
}

func getPartToRemove() string {
	if anon := removePart.Load(); anon != nil {
		return anon.(string)
	}
	return "github.com/CS-SI/SafeScale/"
}

// ----------- log helpers ---------------

const (
	outputErrorTemplate = "%s WITH ERROR [%+v]"
)

var (
	logLevelFnMap = map[logrus.Level]func(args ...interface{}){
		logrus.TraceLevel: logrus.Trace,
		logrus.DebugLevel: logrus.Debug,
		logrus.InfoLevel:  logrus.Info,
		logrus.WarnLevel:  logrus.Warn,
		logrus.ErrorLevel: logrus.Error,
	}
)

// OnExitLogErrorWithLevel returns a function that will log error with the log level wanted
// Intended to be used with defer for example.
func OnExitLogErrorWithLevel(in string, err *error, level logrus.Level) func() {
	logLevelFn, ok := logLevelFnMap[level]
	if !ok {
		logLevelFn = logrus.Error
	}

	// in the meantime if 'in' is empty, recover function name from caller
	if len(in) == 0 {
		if pc, _, _, ok := runtime.Caller(1); ok {
			if f := runtime.FuncForPC(pc); f != nil {
				in = filepath.Base(f.Name())
			}
		}
	}

	return func() {
		if err != nil && *err != nil {
			logLevelFn(fmt.Sprintf(outputErrorTemplate, in, *err))
		}
	}
}

// OnExitLogError returns a function that will log error with level logrus.ErrorLevel.
// Intended to be used with defer for example
func OnExitLogError(in string, err *error) func() {
	return OnExitLogErrorWithLevel(in, err, logrus.ErrorLevel)
}

// OnExitTraceError returns a function that will log error with level logrus.TraceLevel.
// Intended to be used with defer for example.
func OnExitTraceError(in string, err *error) func() {
	return OnExitLogErrorWithLevel(in, err, logrus.TraceLevel)
}

func init() {
	var rootPath string
	if pc, _, _, ok := runtime.Caller(0); ok {
		if f := runtime.FuncForPC(pc); f != nil {
			rootPath = strings.Split(f.Name(), "lib/utils/")[0]
		}
	}
	removePart.Store(rootPath)
}

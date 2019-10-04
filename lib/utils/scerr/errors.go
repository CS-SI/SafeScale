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
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/commonlog"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

var removePart atomic.Value

type consequencer interface {
	Consequences() []error
	AddConsequence(error) error
	Error() string
}

// AddConsequence adds an error 'err' to the list of consequences
func AddConsequence(err error, cons error) error {
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
	if IsGRPCError(err) {
		if IsGRPCTimeout(err) {
			if timeout > 0 {
				return fmt.Errorf("%s took too long (> %v) to respond", action, timeout)
			}
			return fmt.Errorf("%s took too long to respond", action)
		}
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

// IsGRPCTimeout tells if the err is of GRPC kind
func IsGRPCError(err error) bool {
	return grpcstatus.Code(err) != codes.Unknown
}

type fields map[string]interface{}

// ErrCore ...
type ErrCore struct {
	Message      string `json:"message,omitempty"`
	Causer       error  `json:"cause,omitempty"`
	consequences []error
	Fields       fields `json:"fields,omitempty"`
}

func (e ErrCore) FieldsFormatter() string {
	j, err := json.Marshal(e.Fields)

	if err != nil {
		return ""
	}

	return string(j)
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
			e.Causer = cerr.Causer
		}
	}
	return e
}

// Cause returns an error's Causer
func (e ErrCore) Cause() error {
	return e.Causer
}

// Consequences returns the consequences of current error (detected teardown problems)
func (e ErrCore) Consequences() []error {
	return e.consequences
}

// Wrap creates a new error with a message 'message' and a Causer error 'Causer'
func Wrap(cause error, message string) ErrCore {
	return NewErrCore(message, cause, []error{})
}

// NewErrCore creates a new error with a message 'message', a Causer error 'Causer' and a list of teardown problems 'consequences'
func NewErrCore(message string, cause error, consequences []error) ErrCore {
	if consequences == nil {
		return ErrCore{
			Message:      message,
			Causer:       cause,
			consequences: []error{},
			Fields:       make(fields),
		}
	}

	return ErrCore{
		Message:      message,
		Causer:       cause,
		consequences: consequences,
		Fields:       make(fields),
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

func (e ErrCore) WithField(key string, value interface{}) ErrCore {
	if e.Fields != nil {
		e.Fields[key] = value
	}

	return e
}

// Error returns a human-friendly error explanation
func (e ErrCore) Error() string {
	msgFinal := e.Message

	msgFinal += e.CauseFormatter()

	if len(e.Fields) > 0 {
		msgFinal += "\nWith fields: "
		msgFinal += e.FieldsFormatter()
	}

	return msgFinal
}

type causer interface {
	Cause() error
}

// Cause returns the Causer of an error if it implements the causer interface
func Cause(err error) (resp error) {
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
			Causer:       cause,
			consequences: []error{},
			Fields:       make(fields),
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
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
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
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
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
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
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
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
		},
	}
}

// ErrUnauthorized when action is done without being authenticated first
type ErrUnauthorized struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrUnauthorized) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// UnauthorizedError creates a ErrUnauthorized error
func UnauthorizedError(msg string) ErrUnauthorized {
	return ErrUnauthorized{
		ErrCore: ErrCore{
			Message:      msg,
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
		},
	}
}

// ErrForbidden when action is not allowed.
type ErrForbidden struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrForbidden) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// ForbiddenError creates a ErrForbidden error
func ForbiddenError(msg string) ErrForbidden {
	return ErrForbidden{
		ErrCore: ErrCore{
			Message:      msg,
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
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
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
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
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
		},
	}
}

// ErrOverload when action cannot be honored because provider is overloaded (ie too many requests occured in a given time).
type ErrOverload struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrOverload) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// OverloadError creates a ErrOverload error
func OverloadError(msg string) ErrOverload {
	return ErrOverload{
		ErrCore: ErrCore{
			Message:      msg,
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
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
	return ErrNotImplemented{
		ErrCore: ErrCore{
			Message:      decorateWithCallTrace("not implemented yet:", what, ""),
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
		},
	}
}

// NotImplementedError creates a ErrNotImplemented error
func NotImplementedErrorWithReason(what string, why string) ErrNotImplemented {
	return ErrNotImplemented{
		ErrCore: ErrCore{
			Message:      decorateWithCallTrace("not implemented yet:", what, why),
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
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

// ErrRuntimePanic ...
type ErrRuntimePanic struct {
	ErrCore
}

// RuntimePanicError creates a ErrRuntimePanic error
func RuntimePanicError(msg string) ErrRuntimePanic {
	return ErrRuntimePanic{
		ErrCore: ErrCore{
			Message:      msg,
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
		},
	}
}

// ErrInvalidInstance has to be used when a method is called from an instance equal to nil
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
	return ErrInvalidInstance{
		ErrCore: ErrCore{
			Message:      decorateWithCallTrace("invalid instance:", "", "calling method from a nil pointer"),
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
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
	return ErrInvalidParameter{
		ErrCore: ErrCore{
			Message:      decorateWithCallTrace("invalid parameter:", what, why),
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
		},
	}
}

func decorateWithCallTrace(prefix, what, why string) string {
	const missingPrefixMessage = "uncategorized error occurred:"

	msg := prefix
	if prefix == "" {
		prefix = missingPrefixMessage
	}

	if what != "" {
		msg += " '" + what + "'"
	}

	if pc, file, line, ok := runtime.Caller(2); ok {
		if f := runtime.FuncForPC(pc); f != nil {
			filename := strings.Replace(file, getPartToRemove(), "", 1)
			if what == "" {
				msg += fmt.Sprintf(" %s", filepath.Base(f.Name()))
			} else {
				msg += fmt.Sprintf(" in %s", filepath.Base(f.Name()))
			}
			if why != "" {
				msg += ": " + why
			}
			msg += fmt.Sprintf(" [%s:%d]", filename, line)
		}
	} else {
		if why != "" {
			msg += ": " + why
		}
	}
	msg += "\n" + string(debug.Stack())
	return msg
}

// ErrInvalidInstanceContent has to be used when a property of an instance contains invalid property
type ErrInvalidInstanceContent struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrInvalidInstanceContent) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// InvalidInstanceContentError ...
func InvalidInstanceContentError(what, why string) ErrInvalidInstanceContent {
	return ErrInvalidInstanceContent{
		ErrCore: ErrCore{
			Message:      decorateWithCallTrace("invalid instance content:", what, why),
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
		},
	}
}

// ErrInconsistent is used when data used is inconsistent
type ErrInconsistent struct {
	ErrCore
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrInconsistent) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// InconsistentError creates a ErrInconsistent error
func InconsistentError(msg string) ErrInconsistent {
	return ErrInconsistent{
		ErrCore: ErrCore{
			Message:      decorateWithCallTrace(msg, "", ""),
			Causer:       nil,
			consequences: []error{},
			Fields:       make(fields),
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
	errorOccurred       = "ERROR OCCURRED"
	outputErrorTemplate = "%s " + errorOccurred + ": %+v"
)

// OnExitLogErrorWithLevel returns a function that will log error with the log level wanted
// Intended to be used with defer for example.
func OnExitLogErrorWithLevel(in string, err *error, level logrus.Level) func() {
	if in == "" {
		return func() {}
	}

	logLevelFn, ok := commonlog.LogLevelFnMap[level]
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

// OnPanic returns a function intended to capture panic error and fill the error pointer with a ErrRuntimePanic.
func OnPanic(err *error) func() {
	return func() {
		if x := recover(); x != nil {
			*err = RuntimePanicError(fmt.Sprintf("runtime panic occurred: %+v", x))
		}
	}
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

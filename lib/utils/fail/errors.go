/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package fail

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
)

// consequencer is the interface exposing the methods manipulating consequences
type consequencer interface {
	Consequences() []error      // returns a slice of consequences
	AddConsequence(error) Error // adds a consequence to an error
}

// causer is the interface exposing the methods manipulating cause
type causer interface {
	CauseFormatter(func(Error) string) // defines a function used to format a causer output to string
	Cause() error                      // returns the first immediate cause of an error
	RootCause() error                  // returns the root cause of an error
}

// Error defines the interface of a SafeScale error
type Error interface {
	data.Annotatable
	causer
	consequencer
	error

	UnformattedError() string

	SetAnnotationFormatter(func(data.Annotations) string)

	GRPCCode() codes.Code
	ToGRPCStatus() error

	IsNull() bool

	prependToMessage(string)
}

// errorCore is the implementation of interface Error
type errorCore struct {
	message             string
	cause               error
	causeFormatter      func(Error) string
	annotations         data.Annotations
	annotationFormatter func(data.Annotations) string
	consequences        []error
	grpcCode            codes.Code
	lock                *sync.RWMutex
}

// ErrUnqualified is a generic Error type that has no particulaur signification
type ErrUnqualified struct {
	*errorCore
}

// NewError creates a new failure report
func NewError(msg ...interface{}) Error {
	return &ErrUnqualified{
		errorCore: newError(nil, nil, msg...),
	}
}

// NewErrorWithCause creates a new failure report with a cause
func NewErrorWithCause(cause error, msg ...interface{}) Error {
	return &ErrUnqualified{
		errorCore: newError(cause, nil, msg...),
	}
}

// NewErrorWithCauseAndConsequences creates a new failure report with a cause and a list of teardown problems 'consequences'
func NewErrorWithCauseAndConsequences(cause error, consequences []error, msg ...interface{}) Error {
	return &ErrUnqualified{
		errorCore: newError(cause, consequences, msg...),
	}
}

// newError creates a new failure report with a message 'message', a causer error 'causer' and a list of teardown problems 'consequences'
func newError(cause error, consequences []error, msg ...interface{}) *errorCore {
	if consequences == nil {
		consequences = []error{}
	}
	r := errorCore{
		message:             strprocess.FormatStrings(msg...),
		cause:               cause,
		consequences:        consequences,
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	return &r
}

// IsNull tells if the instance is to be considered as null value
func (e *errorCore) IsNull() bool {
	if e == nil {
		return true
	}

	if e.lock == nil {
		return true
	}

	e.lock.RLock()
	defer e.lock.RUnlock()

	// if there is no message, no cause and causeFormatter is nil, this is not a correctly initialized 'errorCore', so called a null value of 'errorCore'
	if e.message == "" && e.cause == nil && e.causeFormatter == nil && e.annotationFormatter == nil {
		return true
	}
	return false
}

// defaultCauseFormatter generates a string containing information about the causing error and the derived errors while trying to clean up
func defaultCauseFormatter(e Error) string {
	if e == nil {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "errorCore.CauseFormatter()", "from nil", 0))
		return ""
	}

	msgFinal := ""

	errCore, ok := e.(*errorCore)
	if !ok {
		return e.UnformattedError()
	}

	errCore.lock.RLock()
	if errCore.cause != nil {
		switch cerr := errCore.cause.(type) {
		case Error:
			errCore.lock.RUnlock() // nolint
			raw := cerr.UnformattedError()
			errCore.lock.RLock()
			if raw != "" {
				msgFinal += ": " + raw
			}
		default:
			raw := cerr.Error()
			if raw != "" {
				msgFinal += ": " + raw
			}
		}
	}

	lenConseq := uint(len(errCore.consequences))
	if lenConseq > 0 {
		msgFinal += fmt.Sprintf("\nwith consequence%s:\n", strprocess.Plural(lenConseq))
		for ind, con := range errCore.consequences {
			if _, ok := con.(Error); ok {
				msgFinal += "- " + con.(Error).UnformattedError()
				if uint(ind+1) < lenConseq {
					msgFinal += "\n"
				}
			} else {
				msgFinal += "- " + con.Error()
				if uint(ind+1) < lenConseq {
					msgFinal += "\n"
				}
			}
		}
	}
	errCore.lock.RUnlock() // nolint
	return msgFinal
}

// CauseFormatter defines the func uses to format cause to string
func (e *errorCore) CauseFormatter(formatter func(Error) string) {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "errorCore.CauseFormatter", "from null value", 0))
		return
	}
	if formatter == nil {
		logrus.Errorf("invalid nil pointer for parameter 'formatter'")
		return
	}

	e.lock.Lock()
	defer e.lock.Unlock()

	e.causeFormatter = formatter
}

// Unwrap implements the Wrapper interface
func (e errorCore) Unwrap() error {
	e.lock.RLock()
	defer e.lock.RUnlock()

	return e.cause
}

// Cause is just an accessor for internal e.cause
func (e errorCore) Cause() error {
	e.lock.RLock()
	defer e.lock.RUnlock()

	return e.cause
}

// RootCause returns the initial error's cause
func (e *errorCore) RootCause() error {
	return RootCause(e)
}

// defaultAnnotationFormatter ...
func defaultAnnotationFormatter(a data.Annotations) string {
	if a == nil {
		logrus.Errorf(callstack.DecorateWith("invalid parameter: ", "'a'", "cannot be nil", 0))
		return ""
	}
	j, err := json.Marshal(a)

	if err != nil {
		return ""
	}

	return string(j)
}

// Annotations ...
func (e errorCore) Annotations() data.Annotations {
	e.lock.RLock()
	defer e.lock.RUnlock()

	return e.annotations
}

// Annotation ...
func (e errorCore) Annotation(key string) (data.Annotation, bool) {
	e.lock.RLock()
	defer e.lock.RUnlock()

	r, ok := e.annotations[key]
	return r, ok
}

// Annotate ...
// satisfies interface data.Annotatable
func (e *errorCore) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "errorCore.Annotate()", "from null value", 0))
		return e
	}

	e.lock.Lock()
	defer e.lock.Unlock()

	if e.annotations == nil {
		e.annotations = make(data.Annotations)
	}
	e.annotations[key] = value

	return e
}

// SetAnnotationFormatter defines the func to use to format annotations
func (e *errorCore) SetAnnotationFormatter(formatter func(data.Annotations) string) {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "errorCore.SetAnnotationFormatter()", "from null value", 0))
		return
	}
	if formatter == nil {
		logrus.Errorf("invalid nil value for parameter 'formatter'")
		return
	}

	e.lock.Lock()
	defer e.lock.Unlock()

	e.annotationFormatter = formatter
}

// AddConsequence adds an error 'err' to the list of consequences
func (e *errorCore) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "errorCore.AddConsequence()", "from null value", 0))
		return e
	}
	if err != nil {
		e.lock.Lock()
		defer e.lock.Unlock()

		if e.consequences == nil {
			e.consequences = []error{}
		}
		e.consequences = append(e.consequences, err)
	}
	return e
}

// Consequences returns the consequences of current error (detected teardown problems)
func (e errorCore) Consequences() []error {
	e.lock.RLock()
	defer e.lock.RUnlock()

	return e.consequences
}

// Error returns a human-friendly error explanation
// satisfies interface error
func (e *errorCore) Error() string {
	e.lock.RLock()
	defer e.lock.RUnlock()

	msgFinal := e.message

	if e.causeFormatter != nil {
		msgFinal += e.causeFormatter(e)
	}

	if len(e.annotations) > 0 {
		msgFinal += "\nWith annotations: "
		msgFinal += e.annotationFormatter(e.annotations)
	}

	return msgFinal
}

// UnformattedError returns a human-friendly error explanation
// satisfies interface error
func (e *errorCore) UnformattedError() string {
	e.lock.RLock()
	defer e.lock.RUnlock()

	return e.unsafeUnformattedError()
}

// unsafeUnformattedError returns a human-friendly error explanation
// must be applying wisely, no errCore locking inside
func (e *errorCore) unsafeUnformattedError() string {
	msgFinal := e.message

	if len(e.annotations) > 0 {
		msgFinal += "\nWith annotations: "
		msgFinal += e.annotationFormatter(e.annotations)
	}

	return msgFinal
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e errorCore) GRPCCode() codes.Code {
	e.lock.RLock()
	defer e.lock.RUnlock()
	return e.grpcCode
}

// ToGRPCStatus returns a grpcstatus struct from error
func (e errorCore) ToGRPCStatus() error {
	e.lock.RLock()
	defer e.lock.RUnlock()

	return grpcstatus.Errorf(e.GRPCCode(), e.Error())
}

// prependToMessage adds 'msg' as prefix to current message of 'e'
// Note: do not call prependTomessage with an already set lock, it will deadlock
func (e *errorCore) prependToMessage(msg string) {
	if e.IsNull() {
		logrus.Errorf("invalid call of errorCore.prependToMessage() from null instance")
		return
	}

	e.lock.Lock()
	defer e.lock.Unlock()

	e.message = msg + ": " + e.message
}

// ErrWarning defines a ErrWarning error
type ErrWarning struct {
	*errorCore
}

// WarningError returns an ErrWarning instance
func WarningError(cause error, msg ...interface{}) *ErrWarning { // nolint
	r := newError(cause, nil, msg...)
	r.grpcCode = codes.Unknown
	return &ErrWarning{
		errorCore: r,
	}
}

// IsNull tells if the instance is null
func (e *ErrWarning) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrWarning) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "errorCore.AddConsequence()", "from null instance", 0))
		return &ErrWarning{}
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ErrWarning) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrWarning.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrWarning) UnformattedError() string {
	return e.Error()
}

// ErrTimeout defines a ErrTimeout error
type ErrTimeout struct {
	*errorCore
	dur time.Duration
}

// TimeoutError returns an ErrTimeout instance
func TimeoutError(cause error, dur time.Duration, msg ...interface{}) *ErrTimeout {
	message := strprocess.FormatStrings(msg...)
	if dur > 0 {
		limitMsg := fmt.Sprintf("(timeout: %s)", dur)
		if message != "" {
			message += " "
		}
		message += limitMsg
	}

	r := newError(cause, nil, message)
	r.grpcCode = codes.DeadlineExceeded
	return &ErrTimeout{
		errorCore: r,
		dur:       dur,
	}
}

// IsNull tells if the instance is null
func (e *ErrTimeout) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrTimeout) AddConsequence(err error) Error {
	if e == err || e == Cause(err) { // do nothing
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "errorCore.AddConsequence()", "from null instance", 0))
		return &ErrTimeout{}
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ErrTimeout) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrTimeout.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrTimeout) UnformattedError() string {
	return e.Error()
}

// ErrNotFound resource not found error
type ErrNotFound struct {
	*errorCore
}

// NotFoundError creates a ErrNotFound error
func NotFoundError(msg ...interface{}) *ErrNotFound {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.NotFound
	return &ErrNotFound{r}
}

func NotFoundErrorWithCause(cause error, msg ...interface{}) *ErrNotFound {
	r := newError(cause, nil, msg...)
	r.grpcCode = codes.NotFound
	return &ErrNotFound{r}
}

// IsNull tells if the instance is null
func (e *ErrNotFound) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrNotFound) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrNotFound.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ErrNotFound) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrNotFound.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrNotFound) UnformattedError() string {
	return e.Error()
}

// ErrNotAvailable resource not available error
type ErrNotAvailable struct {
	*errorCore
}

// NotAvailableError creates a ErrNotAvailable error
func NotAvailableError(msg ...interface{}) *ErrNotAvailable {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.Unavailable
	return &ErrNotAvailable{r}
}

func NotAvailableErrorWithCause(cause error, msg ...interface{}) *ErrNotAvailable {
	r := newError(cause, nil, msg...)
	r.grpcCode = codes.Unavailable
	return &ErrNotAvailable{r}
}

// IsNull tells if the instance is null
func (e *ErrNotAvailable) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrNotAvailable) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrNotAvailable.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ErrNotAvailable) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrNotAvailable.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrNotAvailable) UnformattedError() string {
	return e.Error()
}

// ErrDuplicate already exists error
type ErrDuplicate struct {
	*errorCore
}

// DuplicateError creates a ErrDuplicate error
func DuplicateError(msg ...interface{}) *ErrDuplicate {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.AlreadyExists
	return &ErrDuplicate{r}
}

func DuplicateErrorWithCause(cause error, msg ...interface{}) *ErrDuplicate {
	r := newError(cause, nil, msg...)
	r.grpcCode = codes.AlreadyExists
	return &ErrDuplicate{r}
}

// IsNull tells if the instance is null
func (e *ErrDuplicate) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrDuplicate) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrDuplicate.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrDuplicate) UnformattedError() string {
	return e.Error()
}

// Annotate ...
// satisfies interface data.Annotatable
func (e *ErrDuplicate) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrDuplicate.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrInvalidRequest ...
type ErrInvalidRequest struct {
	*errorCore
}

// InvalidRequestError creates a ErrInvalidRequest error
func InvalidRequestError(msg ...interface{}) Error {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.InvalidArgument
	return &ErrInvalidRequest{r}
}

// IsNull tells if the instance is null
func (e *ErrInvalidRequest) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrInvalidRequest) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrInvalidRequest.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrInvalidRequest) UnformattedError() string {
	return e.Error()
}

// Annotate overloads errorCore.Annotate() to make sure the type returned is the same as the caller
// satisfies interface data.Annotatable
func (e *ErrInvalidRequest) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrInvalidRequest.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrSyntax ...
type ErrSyntax struct {
	*errorCore
}

// SyntaxError creates a ErrSyntax error
func SyntaxError(msg ...interface{}) *ErrSyntax {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.Internal
	return &ErrSyntax{r}
}

func SyntaxErrorWithCause(cause error, msg ...interface{}) *ErrSyntax {
	r := newError(cause, nil, msg...)
	r.grpcCode = codes.Internal
	return &ErrSyntax{r}
}

// IsNull tells if the instance is null
func (e *ErrSyntax) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrSyntax) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrSyntax.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrSyntax) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrSyntax) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrSyntax.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrNotAuthenticated when action is done without being authenticated first
type ErrNotAuthenticated struct {
	*errorCore
}

// NotAuthenticatedError creates a ErrNotAuthenticated error
func NotAuthenticatedError(msg ...interface{}) *ErrNotAuthenticated {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.Unauthenticated
	return &ErrNotAuthenticated{r}
}

// IsNull tells if the instance is null
func (e *ErrNotAuthenticated) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrNotAuthenticated) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrNotAuthenticated.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrNotAuthenticated) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrNotAuthenticated) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrNotAuthenticated.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrForbidden when action is not allowed.
type ErrForbidden struct {
	*errorCore
}

// ForbiddenError creates a ErrForbidden error
func ForbiddenError(msg ...interface{}) *ErrForbidden {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.PermissionDenied
	return &ErrForbidden{r}
}

// IsNull tells if the instance is null
func (e *ErrForbidden) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrForbidden) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrForbidden.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrForbidden) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrForbidden) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrForbidden.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrAborted is used to signal abortion
type ErrAborted struct {
	*errorCore
}

// AbortedError creates a ErrAborted error
// If err != nil, this err will become the cause of the abortion that can be retrieved using Error.Cause()
func AbortedError(err error, msg ...interface{}) *ErrAborted {
	var message string
	if len(msg) == 0 {
		message = "aborted"
	} else {
		message = strprocess.FormatStrings(msg...)
	}
	r := newError(err, nil, message)
	r.grpcCode = codes.Aborted
	return &ErrAborted{r}
}

// IsNull tells if the instance is null
func (e *ErrAborted) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrAborted) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrAborted.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrAborted) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrAborted) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrAborted.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrOverflow is used when a limit is reached
type ErrOverflow struct {
	*errorCore
	limit uint
}

// OverflowError creates a ErrOverflow error
func OverflowError(err error, limit uint, msg ...interface{}) *ErrOverflow {
	message := strprocess.FormatStrings(msg...)
	if limit > 0 {
		limitMsg := fmt.Sprintf("(limit: %d)", limit)
		if message != "" {
			message += " "
		}
		message += limitMsg
	}
	r := newError(err, nil, message)
	r.grpcCode = codes.OutOfRange
	return &ErrOverflow{
		errorCore: r,
		limit:     limit,
	}
}

// IsNull tells if the instance is null
func (e *ErrOverflow) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrOverflow) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrOverflow.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrOverflow) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrOverflow) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrOverflow.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrOverload when action cannot be honored because provider is overloaded (ie too many requests occurred in a given time).
type ErrOverload struct {
	*errorCore
}

// OverloadError creates a ErrOverload error
func OverloadError(msg ...interface{}) *ErrOverload {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.ResourceExhausted
	return &ErrOverload{r}
}

// IsNull tells if the instance is null
func (e *ErrOverload) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrOverload) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrOverload.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrOverload) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrOverload) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrOverload.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrNotImplemented ...
type ErrNotImplemented struct {
	*errorCore
}

// NotImplementedError creates a ErrNotImplemented report
func NotImplementedError(msg ...interface{}) *ErrNotImplemented {
	r := newError(nil, nil, callstack.DecorateWith("not implemented yet: ", strprocess.FormatStrings(msg...), "", 0))
	r.grpcCode = codes.Unimplemented
	return &ErrNotImplemented{r}
}

// IsNull tells if the instance is null
func (e *ErrNotImplemented) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// NotImplementedErrorWithReason creates a ErrNotImplemented report
func NotImplementedErrorWithReason(what string, why string) Error {
	r := newError(nil, nil, callstack.DecorateWith("not implemented yet:", what, why, 0))
	r.grpcCode = codes.Unimplemented
	return &ErrNotImplemented{r}
}

// AddConsequence ...
func (e *ErrNotImplemented) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrNotImplemented.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrNotImplemented) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrNotImplemented) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrNotImplemented.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrRuntimePanic ...
type ErrRuntimePanic struct {
	*errorCore
}

// RuntimePanicError creates a ErrRuntimePanic error
func RuntimePanicError(pattern string, msg ...interface{}) *ErrRuntimePanic {
	r := newError(fmt.Errorf(pattern, msg...), nil, callstack.DecorateWith(strprocess.FormatStrings(msg...), "", "", 0))
	r.grpcCode = codes.Internal
	// This error is systematically logged
	logrus.Error(r.Error())
	return &ErrRuntimePanic{r}
}

// IsNull tells if the instance is null
func (e *ErrRuntimePanic) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrRuntimePanic) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrRuntimePanic.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrRuntimePanic) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrRuntimePanic) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrRuntimePanic.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrInvalidInstance has to be used when a method is called from an instance equal to nil
type ErrInvalidInstance struct {
	*errorCore
}

// InvalidInstanceError creates a ErrInvalidInstance error
func InvalidInstanceError() *ErrInvalidInstance {
	r := newError(nil, nil, callstack.DecorateWith("invalid instance:", "", "calling method from a nil pointer", 0))
	r.grpcCode = codes.FailedPrecondition
	// Systematically log this kind of error
	logrus.Error(r.Error())
	return &ErrInvalidInstance{r}
}

// IsNull tells if the instance is null
func (e *ErrInvalidInstance) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrInvalidInstance) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrInvalidInstance.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrInvalidInstance) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrInvalidInstance) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrInvalidInstance.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrInvalidParameter ...
type ErrInvalidParameter struct {
	*errorCore
}

// InvalidParameterError ...
func InvalidParameterError(what string, why ...interface{}) *ErrInvalidParameter {
	return invalidParameterError(what, 3, why...)
}

func invalidParameterError(what string, skip uint, why ...interface{}) *ErrInvalidParameter {
	r := newError(nil, nil, callstack.DecorateWith("invalid parameter ", what, strprocess.FormatStrings(why...), skip))
	r.grpcCode = codes.FailedPrecondition
	// Systematically log this kind of error
	logrus.Error(r.Error())
	return &ErrInvalidParameter{r}
}

// InvalidParameterCannotBeNilError is a specialized *ErrInvalidParameter with message "cannot be nil"
func InvalidParameterCannotBeNilError(what string) *ErrInvalidParameter {
	return invalidParameterError(what, 3, "cannot be nil")
}

// InvalidParameterCannotBeEmptyStringError is a specialized *ErrInvalidParameter with message "cannot be empty string"
func InvalidParameterCannotBeEmptyStringError(what string) *ErrInvalidParameter {
	return invalidParameterError(what, 3, "cannot be empty string")
}

// IsNull tells if the instance is null
func (e *ErrInvalidParameter) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrInvalidParameter) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrInvalidParameter.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrInvalidParameter) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrInvalidParameter) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrInvalidParameter.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrInvalidInstanceContent has to be used when a property of an instance contains invalid property
type ErrInvalidInstanceContent struct {
	*errorCore
}

// InvalidInstanceContentError returns an instance of ErrInvalidInstanceContent.
func InvalidInstanceContentError(what, why string) *ErrInvalidInstanceContent {
	r := newError(nil, nil, callstack.DecorateWith("invalid instance content:", what, why, 0))
	r.grpcCode = codes.FailedPrecondition
	// Systematically log this kind of error
	logrus.Error(r.Error())
	return &ErrInvalidInstanceContent{r}
}

// IsNull tells if the instance is null
func (e *ErrInvalidInstanceContent) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrInvalidInstanceContent) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrInvalidInstanceContent.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrInvalidInstanceContent) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrInvalidInstanceContent) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrInvalidInstanceContent.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrInconsistent is used when data used is ErrInconsistent
type ErrInconsistent struct {
	*errorCore
}

// InconsistentError creates a ErrInconsistent error
func InconsistentError(msg ...interface{}) *ErrInconsistent {
	r := newError(nil, nil, callstack.DecorateWith(strprocess.FormatStrings(msg...), "", "", 0))
	r.grpcCode = codes.DataLoss
	return &ErrInconsistent{r}
}

// IsNull tells if the instance is null
func (e *ErrInconsistent) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrInconsistent) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrInconsistent.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrInconsistent) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrInconsistent) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrInconsistent.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrExecution is used when code ErrExecution failed
type ErrExecution struct {
	*errorCore
}

// ExecutionError creates a ErrExecution error
func ExecutionError(exitError error, msg ...interface{}) *ErrExecution {
	r := newError(exitError, nil, msg...)
	r.grpcCode = codes.Internal

	retcode := -1
	stderr := ""
	if ee, ok := exitError.(*exec.ExitError); ok {
		if status, ok := ee.Sys().(syscall.WaitStatus); ok {
			retcode = status.ExitStatus()
		}
		stderr = string(ee.Stderr)
	}
	outErr := &ErrExecution{errorCore: r}
	_ = outErr.Annotate("retcode", retcode).Annotate("stderr", stderr)
	return outErr
}

// IsNull tells if the instance is null
func (e *ErrExecution) IsNull() bool {
	if e == nil {
		return true
	}
	if _, ok := e.Annotation("retcode"); ok {
		return false
	}
	return e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrExecution) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrExecution.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrExecution) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrExecution) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrExecution.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrAlteredNothing is used when an Alter() call changed nothing
type ErrAlteredNothing struct {
	*errorCore
}

// AlteredNothingError creates an ErrAlteredNothing error
func AlteredNothingError(msg ...interface{}) *ErrAlteredNothing {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.PermissionDenied
	return &ErrAlteredNothing{r}
}

// IsNull tells if the instance is null
func (e *ErrAlteredNothing) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrAlteredNothing) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrAlteredNothing.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrAlteredNothing) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrAlteredNothing) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrAlteredNothing.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// ErrUnknown is used when situation is unknown
type ErrUnknown struct {
	*errorCore
}

// UnknownError creates a ErrForbidden error
func UnknownError(msg ...interface{}) *ErrForbidden {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.PermissionDenied
	return &ErrForbidden{r}
}

// IsNull tells if the instance is null
func (e *ErrUnknown) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrUnknown) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrUnknown.AddConsequence()", "from null instance", 0))
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrUnknown) UnformattedError() string {
	return e.Error()
}

// Annotate ...
func (e *ErrUnknown) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf(callstack.DecorateWith("invalid call:", "ErrUnknown.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

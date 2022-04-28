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
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v21/lib/utils/strprocess"
)

// consequencer is the interface exposing the methods manipulating consequences
type consequencer interface {
	Consequences() []error      // returns a slice of consequences
	AddConsequence(error) Error // adds a consequence to an error
}

// causer is the interface exposing the methods manipulating cause
type causer interface {
	Cause() error     // returns the first immediate cause of an error
	RootCause() error // returns the root cause of an error
}

// DISABLED go:generate minimock -o mocks/mock_error.go -i github.com/CS-SI/SafeScale/v21/lib/utils/fail.Error

// Error defines the interface of a SafeScale error
type Error interface {
	data.Annotatable
	causer
	consequencer
	error
	data.NullValue
	data.Validatable

	UnformattedError() string
	ToGRPCStatus() error
}

const EmbeddedErrorStructName = "errorCore"

// errorCore is the implementation of interface Error
type errorCore struct {
	message             string
	cause               error
	causeFormatter      func(Error) string
	annotations         data.Annotations
	annotationFormatter func(data.Annotations) (string, error)
	consequences        []error
	grpcCode            codes.Code
	lock                *sync.RWMutex
}

func IgnoreError(in interface{}, _ Error) interface{} {
	return in
}

func TakeError(_ interface{}, xerr Error) error { // nolint
	return xerr
}

// Valid errorCore struct should be always created via newError constructor, if it doesn't we might miss e.lock initialization
func (e errorCore) Valid() bool {
	err := validation.ValidateStruct(&e,
		// grpcCode max value is 17
		validation.Field(&e.grpcCode, validation.Required, validation.Max(uint32(17))),
		// Lock cannot be nil
		validation.Field(&e.lock, validation.Required, validation.NotNil),
	)
	if err != nil {
		logrus.Errorf("validation error: %v", err)
		return false
	}
	return true
}

// ErrUnqualified is a generic Error type that has no particular signification
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
		message:             strings.TrimSpace(strprocess.FormatStrings(msg...)),
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
	msgFinal := ""

	if e == nil || valid.IsNil(e) {
		return ""
	}

	errCore, ok := e.(*errorCore)
	if !ok {
		return e.UnformattedError()
	}

	errCore.lock.RLock()
	if errCore.cause != nil {
		switch cerr := errCore.cause.(type) {
		case Error:
			errCore.lock.RUnlock() // nolint
			raw := cerr.Error()
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
			if con != nil {
				if _, ok := con.(Error); ok {
					msgFinal += "- " + con.(Error).Error()
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
	}
	errCore.lock.RUnlock() // nolint
	return msgFinal
}

// setCauseFormatter defines the func uses to format cause into a string
func (e *errorCore) setCauseFormatter(formatter func(Error) string) error {
	if valid.IsNil(e) {
		return fmt.Errorf(callstack.DecorateWith("invalid call", "errorCore.setCauseFormatter", "from null value", 0))
	}
	if formatter == nil {
		return fmt.Errorf("invalid nil pointer for parameter 'formatter'")
	}

	e.lock.Lock()
	defer e.lock.Unlock()

	e.causeFormatter = formatter
	return nil
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
func (e errorCore) RootCause() error {
	return RootCause(&e)
}

// defaultAnnotationFormatter ...
func defaultAnnotationFormatter(a data.Annotations) (string, error) {
	if a == nil {
		return "", fmt.Errorf(callstack.DecorateWith("invalid parameter", "'a'", "cannot be nil", 0))
	}
	j, err := json.Marshal(a)

	if err != nil {
		return "", err
	}

	return string(j), nil
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

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
// satisfies interface data.Annotatable
func (e *errorCore) Annotate(key string, value data.Annotation) data.Annotatable {
	e.lock.Lock()
	defer e.lock.Unlock()

	if e.annotations == nil {
		e.annotations = make(data.Annotations)
	}
	e.annotations[key] = value

	return e
}

// setAnnotationFormatter defines the func to use to format annotations
func (e *errorCore) setAnnotationFormatter(formatter func(data.Annotations) (string, error)) error {
	if valid.IsNil(e) {
		return fmt.Errorf(callstack.DecorateWith("invalid call", "errorCore.setAnnotationFormatter()", "from null value", 0))
	}
	if formatter == nil {
		return fmt.Errorf("invalid nil value for parameter 'formatter'")
	}

	e.lock.Lock()
	defer e.lock.Unlock()

	e.annotationFormatter = formatter
	return nil
}

// AddConsequence adds an error 'err' to the list of consequences
func (e *errorCore) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
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
func (e *errorCore) Error() string {
	e.lock.RLock()
	defer e.lock.RUnlock()

	msgFinal := e.message

	if e.causeFormatter != nil {
		sta := string(debug.Stack())
		num := strings.Count(sta, "(*errorCore).Error") // protection against recursive calls infinite loop
		if num < 32 {
			msgFinal += e.causeFormatter(e)
		}
	}

	if len(e.annotations) > 0 {
		sta := string(debug.Stack())
		num := strings.Count(sta, "(*errorCore).Error") // protection against recursive calls infinite loop
		if num < 32 {
			msgFinal += "\nWith annotations: "
			more, fmtErr := e.annotationFormatter(e.annotations)
			if fmtErr != nil {
				return msgFinal
			}
			msgFinal += more
		}
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
		more, fmtErr := e.annotationFormatter(e.annotations)
		if fmtErr != nil {
			return msgFinal
		}
		msgFinal += more
	}

	return msgFinal
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *errorCore) getGRPCCode() codes.Code {
	e.lock.RLock()
	defer e.lock.RUnlock()
	return e.grpcCode
}

// ToGRPCStatus returns a grpcstatus struct from error
func (e errorCore) ToGRPCStatus() error {
	e.lock.RLock()
	defer e.lock.RUnlock()

	return grpcstatus.Errorf(e.getGRPCCode(), e.Error())
}

// ErrWarning defines an ErrWarning error
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

// WarningErrorWithCauseAndConsequences return an ErrWarning instance
func WarningErrorWithCauseAndConsequences(cause error, consequences []error, msg ...interface{}) *ErrWarning { // nolint
	r := newError(cause, consequences, msg...)
	r.grpcCode = codes.Unknown
	return &ErrWarning{
		errorCore: r,
	}
}

// IsNull tells if the instance is null
func (e *ErrWarning) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrWarning) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrWarning) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrWarning) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrWarning) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
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

// TimeoutErrorWithCauseAndConsequences returns an ErrTimeout instance
func TimeoutErrorWithCauseAndConsequences(cause error, dur time.Duration, consequences []error, msg ...interface{}) *ErrTimeout {
	message := strprocess.FormatStrings(msg...)
	r := newError(cause, consequences, message)
	r.grpcCode = codes.DeadlineExceeded
	return &ErrTimeout{
		errorCore: r,
		dur:       dur,
	}
}

// IsNull tells if the instance is null
func (e *ErrTimeout) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrTimeout) AddConsequence(err error) Error {
	if e == err || e == Cause(err) { // do nothing
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrTimeout) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrTimeout) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrTimeout) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrNotFound resource not found error
type ErrNotFound struct {
	*errorCore
}

// NotFoundError creates an ErrNotFound error
func NotFoundError(msg ...interface{}) *ErrNotFound {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.NotFound
	return &ErrNotFound{r}
}

// NotFoundErrorWithCause creates an ErrNotFound error initialized with cause 'cause'
func NotFoundErrorWithCause(cause error, consequences []error, msg ...interface{}) *ErrNotFound {
	r := newError(cause, consequences, msg...)
	r.grpcCode = codes.NotFound
	return &ErrNotFound{r}
}

// IsNull tells if the instance is null
func (e *ErrNotFound) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrNotFound) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrNotFound) Annotate(key string, value data.Annotation) data.Annotatable {
	if valid.IsNil(e) {
		logrus.Errorf(callstack.DecorateWith("invalid call", "ErrNotFound.Annotate()", "from null instance", 0))
		return e
	}
	e.errorCore.Annotate(key, value)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrNotFound) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrNotFound) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrNotAvailable resource not available error
type ErrNotAvailable struct {
	*errorCore
}

// NotAvailableError creates an ErrNotAvailable error
func NotAvailableError(msg ...interface{}) *ErrNotAvailable {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.Unavailable
	return &ErrNotAvailable{r}
}

// NotAvailableErrorWithCause creates an ErrNotAvailable error initialized with a cause 'cause'
func NotAvailableErrorWithCause(cause error, consequences []error, msg ...interface{}) *ErrNotAvailable {
	r := newError(cause, consequences, msg...)
	r.grpcCode = codes.Unavailable
	return &ErrNotAvailable{r}
}

// IsNull tells if the instance is null
func (e *ErrNotAvailable) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrNotAvailable) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrNotAvailable) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrNotAvailable) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrNotAvailable) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrDuplicate already exists error
type ErrDuplicate struct {
	*errorCore
}

// DuplicateError creates an ErrDuplicate error
func DuplicateError(msg ...interface{}) *ErrDuplicate {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.AlreadyExists
	return &ErrDuplicate{r}
}

// DuplicateErrorWithCause creates an ErrDuplicate error initialized with cause 'cause'
func DuplicateErrorWithCause(cause error, consequences []error, msg ...interface{}) *ErrDuplicate {
	r := newError(cause, consequences, msg...)
	r.grpcCode = codes.AlreadyExists
	return &ErrDuplicate{r}
}

// IsNull tells if the instance is null
func (e *ErrDuplicate) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrDuplicate) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrDuplicate) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
// satisfies interface data.Annotatable
func (e *ErrDuplicate) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrDuplicate) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrInvalidRequest ...
type ErrInvalidRequest struct {
	*errorCore
}

// InvalidRequestError creates an ErrInvalidRequest error
func InvalidRequestError(msg ...interface{}) Error {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.InvalidArgument
	return &ErrInvalidRequest{r}
}

// InvalidRequestErrorWithCause creates an ErrInvalidRequest error
func InvalidRequestErrorWithCause(cause error, consequences []error, msg ...interface{}) Error {
	r := newError(cause, consequences, msg...)
	r.grpcCode = codes.InvalidArgument
	return &ErrInvalidRequest{r}
}

// IsNull tells if the instance is null
func (e *ErrInvalidRequest) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrInvalidRequest) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrInvalidRequest) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// Annotate overloads errorCore.Annotate() to make sure the type returned is the same as the caller
// satisfies interface data.Annotatable
func (e *ErrInvalidRequest) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrInvalidRequest) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrSyntax ...
type ErrSyntax struct {
	*errorCore
}

// SyntaxError creates an ErrSyntax error
func SyntaxError(msg ...interface{}) *ErrSyntax {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.Internal
	return &ErrSyntax{r}
}

// SyntaxErrorWithCause creates an ErrSyntax error initialized with cause 'cause'
func SyntaxErrorWithCause(cause error, consequences []error, msg ...interface{}) *ErrSyntax {
	r := newError(cause, consequences, msg...)
	r.grpcCode = codes.Internal
	return &ErrSyntax{r}
}

// IsNull tells if the instance is null
func (e *ErrSyntax) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrSyntax) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrSyntax) UnformattedError() string {
	if valid.IsNil(e) {
		return ""
	}
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrSyntax) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrSyntax) getGRPCCode() codes.Code {
	if valid.IsNil(e) {
		logrus.Errorf(callstack.DecorateWith("invalid call", "errorCore.getGRPCCode()", "from null instance", 0))
		return codes.InvalidArgument
	}
	return e.errorCore.getGRPCCode()
}

// ErrNotAuthenticated when action is done without being authenticated first
type ErrNotAuthenticated struct {
	*errorCore
}

// NotAuthenticatedError creates an ErrNotAuthenticated error
func NotAuthenticatedError(msg ...interface{}) *ErrNotAuthenticated {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.Unauthenticated
	return &ErrNotAuthenticated{r}
}

// NotAuthenticatedErrorWithCause creates an ErrNotAuthenticated error
func NotAuthenticatedErrorWithCause(cause error, consequences []error, msg ...interface{}) *ErrNotAuthenticated {
	r := newError(cause, consequences, msg...)
	r.grpcCode = codes.Unauthenticated
	return &ErrNotAuthenticated{r}
}

// IsNull tells if the instance is null
func (e *ErrNotAuthenticated) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrNotAuthenticated) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrNotAuthenticated) UnformattedError() string {
	if valid.IsNil(e) {
		return ""
	}
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrNotAuthenticated) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrNotAuthenticated) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrForbidden when action is not allowed.
type ErrForbidden struct {
	*errorCore
}

// ForbiddenError creates an ErrForbidden error
func ForbiddenError(msg ...interface{}) *ErrForbidden {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.PermissionDenied
	return &ErrForbidden{r}
}

// ForbiddenErrorWithCause creates an ErrForbidden error
func ForbiddenErrorWithCause(cause error, consequences []error, msg ...interface{}) *ErrForbidden {
	r := newError(cause, consequences, msg...)
	r.grpcCode = codes.PermissionDenied
	return &ErrForbidden{r}
}

// IsNull tells if the instance is null
func (e *ErrForbidden) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrForbidden) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrForbidden) UnformattedError() string {
	if valid.IsNil(e) {
		return ""
	}
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrForbidden) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrForbidden) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrAborted is used to signal abortion
type ErrAborted struct {
	*errorCore
}

// AbortedError creates an ErrAborted error
// If err != nil, 'err' will become the cause of the abortion that can be retrieved using Error.Cause()
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

// AbortedErrorWithCauseAndConsequences creates an ErrAborted error
func AbortedErrorWithCauseAndConsequences(err error, consequences []error, msg ...interface{}) *ErrAborted {
	var message string
	if len(msg) == 0 {
		message = "aborted"
	} else {
		message = strprocess.FormatStrings(msg...)
	}
	r := newError(err, consequences, message)
	r.grpcCode = codes.Aborted
	return &ErrAborted{r}
}

// IsNull tells if the instance is null
func (e *ErrAborted) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrAborted) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrAborted) UnformattedError() string {
	if valid.IsNil(e) {
		return ""
	}
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrAborted) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrAborted) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrOverflow is used when a limit is reached
type ErrOverflow struct {
	*errorCore
	limit uint
}

// OverflowError creates an ErrOverflow error
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

// OverflowErrorWithCause creates an ErrOverflow error
func OverflowErrorWithCause(err error, limit uint, consequences []error, msg ...interface{}) *ErrOverflow {
	message := strprocess.FormatStrings(msg...)
	if limit > 0 {
		limitMsg := fmt.Sprintf("(limit: %d)", limit)
		if message != "" {
			message += " "
		}
		message += limitMsg
	}
	r := newError(err, consequences, message)
	r.grpcCode = codes.OutOfRange
	return &ErrOverflow{
		errorCore: r,
		limit:     limit,
	}
}

// IsNull tells if the instance is null
func (e *ErrOverflow) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrOverflow) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrOverflow) UnformattedError() string {
	if valid.IsNil(e) {
		return ""
	}
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrOverflow) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrOverflow) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrOverload when action cannot be honored because provider is overloaded (ie too many requests occurred in a given time).
type ErrOverload struct {
	*errorCore
}

// OverloadError creates an ErrOverload error
func OverloadError(msg ...interface{}) *ErrOverload {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.ResourceExhausted
	return &ErrOverload{r}
}

// OverloadErrorWithCause creates an ErrOverload error
func OverloadErrorWithCause(cause error, consequences []error, msg ...interface{}) *ErrOverload {
	r := newError(cause, consequences, msg...)
	r.grpcCode = codes.ResourceExhausted
	return &ErrOverload{r}
}

// IsNull tells if the instance is null
func (e *ErrOverload) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrOverload) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrOverload) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrOverload) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrOverload) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrNotImplemented ...
type ErrNotImplemented struct {
	*errorCore
}

// NotImplementedError creates an ErrNotImplemented report
func NotImplementedError(msg ...interface{}) *ErrNotImplemented {
	r := newError(nil, nil, callstack.DecorateWith("not implemented yet: ", strprocess.FormatStrings(msg...), "", 0))
	r.grpcCode = codes.Unimplemented
	return &ErrNotImplemented{r}
}

// IsNull tells if the instance is null
func (e *ErrNotImplemented) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// NotImplementedErrorWithCauseAndConsequences creates an ErrNotImplemented report
func NotImplementedErrorWithCauseAndConsequences(cause error, consequences []error, msg ...interface{}) Error {
	r := newError(cause, consequences, callstack.DecorateWith("not implemented yet:", strprocess.FormatStrings(msg...), "", 0))
	r.grpcCode = codes.Unimplemented
	return &ErrNotImplemented{r}
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrNotImplemented) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrNotImplemented) UnformattedError() string {
	if valid.IsNil(e) {
		return ""
	}
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrNotImplemented) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrNotImplemented) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrRuntimePanic ...
type ErrRuntimePanic struct {
	*errorCore
}

// RuntimePanicError creates an ErrRuntimePanic error
func RuntimePanicError(pattern string, msg ...interface{}) *ErrRuntimePanic {
	here := callstack.DecorateWith(strprocess.FormatStrings(msg...), "panicked", "", 4)
	r := newError(fmt.Errorf(pattern, msg...), nil, here)
	r.grpcCode = codes.Internal
	// This error is systematically logged
	logrus.Error(r.Error())
	return &ErrRuntimePanic{r}
}

// RuntimePanicErrorWithCauseAndConsequences creates an ErrRuntimePanic error
func RuntimePanicErrorWithCauseAndConsequences(cause error, consequences []error, overwrite bool, msg ...interface{}) *ErrRuntimePanic {
	var r *errorCore
	if overwrite {
		point := callstack.DecorateWith(strprocess.FormatStrings(msg...), "panicked", "", 4)
		r = newError(cause, consequences, point)
		r.grpcCode = codes.Internal
		// This error is systematically logged
		logrus.Error(r.Error())
	} else {
		r = newError(cause, consequences, msg...)
		r.grpcCode = codes.Internal
	}

	return &ErrRuntimePanic{r}
}

// IsNull tells if the instance is null
func (e *ErrRuntimePanic) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrRuntimePanic) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrRuntimePanic) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrRuntimePanic) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrRuntimePanic) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrInvalidInstance has to be used when a method is called from an instance equal to nil
type ErrInvalidInstance struct {
	*errorCore
}

// InvalidInstanceError creates an ErrInvalidInstance error
func InvalidInstanceError() *ErrInvalidInstance {
	r := newError(nil, nil, callstack.DecorateWith("invalid instance", "", "calling method from a nil pointer", 0))
	r.grpcCode = codes.FailedPrecondition
	// Systematically log this kind of error
	logrus.Error(r.Error())
	return &ErrInvalidInstance{r}
}

// InvalidInstanceErrorWithCause creates an ErrInvalidInstance error
func InvalidInstanceErrorWithCause(cause error, consequences []error, msg ...interface{}) *ErrInvalidInstance {
	r := newError(cause, consequences, callstack.DecorateWith("invalid instance", "", "calling method from a nil pointer", 0))
	r.grpcCode = codes.FailedPrecondition
	return &ErrInvalidInstance{r}
}

// IsNull tells if the instance is null
func (e *ErrInvalidInstance) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrInvalidInstance) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrInvalidInstance) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrInvalidInstance) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrInvalidInstance) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrInvalidParameter ...
type ErrInvalidParameter struct {
	*errorCore
	what string
	skip uint
}

// InvalidParameterError creates an ErrInvalidParameter error
func InvalidParameterError(what string, why ...interface{}) *ErrInvalidParameter {
	return invalidParameterError(what, 3, why...)
}

func invalidParameterError(what string, skip uint, why ...interface{}) *ErrInvalidParameter {
	r := newError(nil, nil, callstack.DecorateWith("invalid parameter", what, strprocess.FormatStrings(why...), skip))
	r.grpcCode = codes.InvalidArgument
	// Systematically log this kind of error
	logrus.Error(r.Error())
	return &ErrInvalidParameter{
		errorCore: r,
		what:      what,
		skip:      skip,
	}
}

// InvalidParameterErrorWithCauseAndConsequences creates an ErrInvalidParameter error
func InvalidParameterErrorWithCauseAndConsequences(cause error, consequences []error, what string, skip uint, why ...interface{}) *ErrInvalidParameter {
	r := newError(cause, consequences, callstack.DecorateWith("invalid parameter", what, strprocess.FormatStrings(why...), skip))
	r.grpcCode = codes.InvalidArgument
	return &ErrInvalidParameter{errorCore: r,
		what: what,
		skip: skip,
	}
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
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrInvalidParameter) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrInvalidParameter) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrInvalidParameter) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrInvalidParameter) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrInvalidInstanceContent has to be used when a property of an instance contains invalid property
type ErrInvalidInstanceContent struct {
	*errorCore
	what string
	why  string
}

// InvalidInstanceContentError returns an instance of ErrInvalidInstanceContent.
func InvalidInstanceContentError(what, why string) *ErrInvalidInstanceContent {
	r := newError(nil, nil, callstack.DecorateWith("invalid instance content", what, why, 0))
	r.grpcCode = codes.FailedPrecondition
	// Systematically log this kind of error
	logrus.Error(r.Error())
	return &ErrInvalidInstanceContent{
		errorCore: r,
		what:      what,
		why:       why,
	}
}

// InvalidInstanceContentErrorWithCause returns an instance of ErrInvalidInstanceContent.
func InvalidInstanceContentErrorWithCause(cause error, consequences []error, what, why string, msg ...interface{}) *ErrInvalidInstanceContent {
	r := newError(cause, consequences, callstack.DecorateWith("invalid instance content", what, why, 0))
	r.grpcCode = codes.FailedPrecondition
	return &ErrInvalidInstanceContent{
		errorCore: r,
		what:      what,
		why:       why,
	}
}

// IsNull tells if the instance is null
func (e *ErrInvalidInstanceContent) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrInvalidInstanceContent) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrInvalidInstanceContent) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrInvalidInstanceContent) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrInvalidInstanceContent) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrInconsistent is used when data used is ErrInconsistent
type ErrInconsistent struct {
	*errorCore
}

// InconsistentError creates an ErrInconsistent error
func InconsistentError(msg ...interface{}) *ErrInconsistent {
	r := newError(nil, nil, callstack.DecorateWith(strprocess.FormatStrings(msg...), "", "", 0))
	r.grpcCode = codes.DataLoss
	return &ErrInconsistent{r}
}

// InconsistentErrorWithCause creates an ErrInconsistent error
func InconsistentErrorWithCause(cause error, consequences []error, msg ...interface{}) *ErrInconsistent {
	r := newError(cause, consequences, callstack.DecorateWith(strprocess.FormatStrings(msg...), "", "", 0))
	r.grpcCode = codes.DataLoss
	return &ErrInconsistent{r}
}

// IsNull tells if the instance is null
func (e *ErrInconsistent) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrInconsistent) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrInconsistent) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrInconsistent) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrInconsistent) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrExecution is used when code ErrExecution failed
type ErrExecution struct {
	*errorCore
}

// ExecutionError creates an ErrExecution error
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

// ExecutionErrorWithCause creates an ErrExecution error
func ExecutionErrorWithCause(exitError error, consequences []error, msg ...interface{}) *ErrExecution {
	r := newError(exitError, consequences, msg...)
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
	return valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrExecution) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrExecution) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrExecution) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrExecution) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
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

// AlteredNothingErrorWithCause creates an ErrAlteredNothing error
func AlteredNothingErrorWithCause(cause error, consequences []error, msg ...interface{}) *ErrAlteredNothing {
	r := newError(cause, consequences, msg...)
	r.grpcCode = codes.PermissionDenied
	return &ErrAlteredNothing{r}
}

// IsNull tells if the instance is null
func (e *ErrAlteredNothing) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrAlteredNothing) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrAlteredNothing) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrAlteredNothing) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrAlteredNothing) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

// ErrUnknown is used when situation is unknown
type ErrUnknown struct {
	*errorCore
}

// UnknownError creates an ErrUnknown error
func UnknownError(msg ...interface{}) *ErrUnknown {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.Unknown
	return &ErrUnknown{r}
}

// UnknownErrorWithCause creates an ErrUnknown error
func UnknownErrorWithCause(cause error, consequences []error, msg ...interface{}) *ErrUnknown {
	r := newError(cause, consequences, msg...)
	r.grpcCode = codes.Unknown
	return &ErrUnknown{r}
}

// IsNull tells if the instance is null
func (e *ErrUnknown) IsNull() bool {
	return e == nil || valid.IsNil(e.errorCore)
}

// AddConsequence adds a consequence 'err' to current error 'e'
func (e *ErrUnknown) AddConsequence(err error) Error {
	if e == err || e == Cause(err) {
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// UnformattedError returns Error() without any extra formatting applied
func (e *ErrUnknown) UnformattedError() string {
	return e.unsafeUnformattedError()
}

// Annotate adds an Annotation (key-value) pair to current error 'e', using the key 'key' and the value 'value'
func (e *ErrUnknown) Annotate(key string, value data.Annotation) data.Annotatable {
	e.errorCore.Annotate(key, value)
	return e
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *ErrUnknown) getGRPCCode() codes.Code {
	return e.errorCore.getGRPCCode()
}

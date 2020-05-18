/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"encoding/json"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
)

// Error defines the interface of a SafeScale error
type Error interface {
	data.NullValue
	data.Annotatable
	error

	CauseFormatter(func(Error) string)
	Cause() error

	// ConsequenceFormatter(func(Error) string)
	AddConsequence(err error) Error
	Consequences() []error

	AnnotationFormatter(func(data.Annotations) string)

	// Error() string   // VPL: comes from error...

	GRPCCode() codes.Code
	ToGRPCStatus() error
}

// errorCore is the implementation of interface Error
type errorCore struct {
	message             string
	causer              error
	causeFormatter      func(Error) string
	annotations         data.Annotations
	annotationFormatter func(data.Annotations) string
	consequences        []error
	// consequenceFormatter func(Error) string
	grpcCode codes.Code
}

// NewError creates a new failure report
func NewError(msg ...interface{}) Error {
	return newError(nil, nil, msg...)
}

// NewErrorWithCause creates a new failure report with a cause
func NewErrorWithCause(cause error, msg ...interface{}) Error {
	return newError(cause, nil, msg...)
}

// NewErrorWithCauseAndConsequences creates a new failure report with a cause and a list of teardown problems 'consequences'
func NewErrorWithCauseAndConsequences(cause error, consequences []error, msg ...interface{}) Error {
	return newError(cause, consequences, msg...)
}

// newError creates a new failure report with a message 'message', a causer error 'causer' and a list of teardown problems 'consequences'
func newError(cause error, consequences []error, msg ...interface{}) *errorCore {
	if consequences == nil {
		consequences = []error{}
	}
	r := errorCore{
		message:      strprocess.FormatStrings(msg...),
		causer:       cause,
		consequences: consequences,
		annotations:  make(data.Annotations),
		grpcCode:     codes.Unknown,
	}
	r.causeFormatter = defaultCauseFormatter
	// r.consequenceFormatter = defaultConsequenceFormatter
	r.annotationFormatter = defaultAnnotationFormatter
	return &r
}

// // Pointer returns a pointer to Error previously casted to error
// func Pointer(err Error) *error {
// 	casted := err.(error)
// 	return &casted
// }

// IsNull tells if the instance is null
func (e *errorCore) IsNull() bool {
	return e == nil || e.message == ""
}

// defaultCauseFormatter generates a string containing information about the causing error and the derived errors while trying to clean up
func defaultCauseFormatter(e Error) string {
	if e.IsNull() {
		logrus.Errorf("invalid call of errorCore.CauseFormatter() from null instance")
		return ""
	}

	msgFinal := ""

	if e.Cause() != nil {
		msgFinal += ": "
		msgFinal += e.Cause().Error()
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

// CauseFormatter defines the func uses to format cause to string
func (e *errorCore) CauseFormatter(formatter func(Error) string) {
	if e.IsNull() {
		logrus.Errorf("invalid call to errorCore.CauseFormatter from null instance")
		return
	}
	if formatter == nil {
		logrus.Errorf("invalid nil pointer for parameter 'formatter'")
		return
	}
	e.causeFormatter = formatter
}

// Cause returns an error's cause
func (e errorCore) Cause() error {
	if e.IsNull() {
		logrus.Errorf("invalid call of errorCore.Cause() from null instance")
		return nil
	}
	return e.causer
}

// defaultAnnotationFormatter ...
func defaultAnnotationFormatter(a data.Annotations) string {
	if a == nil {
		logrus.Errorf("invalid nil pointer for parameter 'a'")
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
	if e.IsNull() {
		logrus.Errorf("invalid call of errorCore.Annotations() from null instance")
		return nil
	}
	return e.annotations
}

// Annotation ...
func (e errorCore) Annotation(key string) (data.Annotation, bool) {
	if e.IsNull() {
		logrus.Errorf("invalid call of errorCore.Annotation() from null instance")
		return nil, false
	}
	r, ok := e.annotations[key]
	return r, ok
}

// Annotate ...
// satisfies interface data.Annotatable
func (e *errorCore) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of errorCore.Annotate() from null instance")
		return &errorCore{}
	}

	if e.annotations != nil {
		e.annotations[key] = value
	}

	return e
}

// AnnotationFormatter defines the func to use to format annotations
func (e *errorCore) AnnotationFormatter(formatter func(data.Annotations) string) {
	if e.IsNull() {
		logrus.Errorf("invalid call of errorCore.DefineAnnotationFormatter from null instance")
		return
	}
	if formatter == nil {
		logrus.Errorf("invalid nil value for parameter 'formatter'")
		return
	}
	e.annotationFormatter = formatter
}

// AddConsequence adds an error 'err' to the list of consequences
func (e *errorCore) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of errorCore.AddConsequence() from null instance")
		return &errorCore{}
	}
	if err != nil {
		if e.consequences == nil {
			e.consequences = []error{}
		}
		e.consequences = append(e.consequences, err)
	}
	return e
}

// Consequences returns the consequences of current error (detected teardown problems)
func (e errorCore) Consequences() []error {
	if e.IsNull() {
		logrus.Errorf("invalid call of errorCore.Consequences() from null instance")
		return nil
	}
	return e.consequences
}

// Error returns a human-friendly error explanation
// satisfies interface error
func (e *errorCore) Error() string {
	if e.IsNull() {
		logrus.Errorf("invalid call of errorCore.Error() from null instance")
		return ""
	}

	msgFinal := e.message

	msgFinal += e.causeFormatter(e)

	if len(e.annotations) > 0 {
		msgFinal += "\nWith annotations: "
		msgFinal += e.annotationFormatter(e.annotations)
	}

	return msgFinal
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e errorCore) GRPCCode() codes.Code {
	if e.IsNull() {
		logrus.Errorf("invalid call of errorCore.GRPCCode() from null instance")
		return codes.Unknown
	}
	return e.grpcCode
}

// ToGRPCStatus returns a grpcstatus struct from error
func (e errorCore) ToGRPCStatus() error {
	if e.IsNull() {
		logrus.Errorf("invalid call of errorCore.ToGRPCStatus() from null instance")
		return nil
	}
	return grpcstatus.Errorf(e.GRPCCode(), e.Error())
}

// ErrTimeout defines a ErrTimeout error
type ErrTimeout = *ImplTimeout
type ImplTimeout struct {
	*errorCore
	dur time.Duration
}

// TimeoutError returns an ErrTimeout instance
func TimeoutError(cause error, dur time.Duration, msg ...interface{}) Error {
	r := newError(cause, nil, msg...)
	r.grpcCode = codes.DeadlineExceeded
	return &ImplTimeout{
		errorCore: r,
		dur:       dur,
	}
}

// IsNull tells if the instance is null
func (e *ImplTimeout) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplTimeout) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrTimeout.AddConsequence() from null instance")
		return &ImplTimeout{}
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplTimeout) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrTimeout.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrNotFound resource not found error
type ErrNotFound = *ImplNotFound
type ImplNotFound struct {
	*errorCore
}

// NotFoundError creates a ErrNotFound error
func NotFoundError(msg ...interface{}) Error {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.NotFound
	return &ImplNotFound{r}
}

// IsNull tells if the instance is null
func (e *ImplNotFound) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplNotFound) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrNotFound.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplNotFound) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrNotFound.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrNotAvailable resource not available error
type ErrNotAvailable = *ImplNotAvailable
type ImplNotAvailable struct {
	*errorCore
}

// NotAvailableError creates a ErrNotAvailable error
func NotAvailableError(msg ...interface{}) Error {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.Unavailable
	return &ImplNotAvailable{r}
}

// IsNull tells if the instance is null
func (e *ImplNotAvailable) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplNotAvailable) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrNotAvailable.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplNotAvailable) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrNotAvailable.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrDuplicate already exists error
type ErrDuplicate = *ImplDuplicate
type ImplDuplicate struct {
	*errorCore
}

// DuplicateError creates a ErrDuplicate error
func DuplicateError(msg ...interface{}) Error {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.AlreadyExists
	return &ImplDuplicate{r}
}

// IsNull tells if the instance is null
func (e *ImplDuplicate) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplDuplicate) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrDuplicate.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
// satisfies interface data.Annotatable
func (e *ImplDuplicate) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrDuplicate.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrInvalidRequest ...
type ErrInvalidRequest = *ImplInvalidRequest
type ImplInvalidRequest struct {
	*errorCore
}

// InvalidRequestError creates a ErrInvalidRequest error
func InvalidRequestError(msg ...interface{}) Error {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.InvalidArgument
	return &ImplInvalidRequest{r}
}

// IsNull tells if the instance is null
func (e *ImplInvalidRequest) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplInvalidRequest) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrInvalidRequest.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate overloads errorCore.Annotate() to make sure the type returned is the same as the caller
// satisfies interface data.Annotatable
func (e *ImplInvalidRequest) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrInvalidRequest.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrSyntax ...
type ErrSyntax = *ImplSyntax
type ImplSyntax struct {
	*errorCore
}

// SyntaxError creates a ErrSyntax error
func SyntaxError(msg ...interface{}) Error {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.Internal
	return &ImplSyntax{r}
}

// IsNull tells if the instance is null
func (e *ImplSyntax) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplSyntax) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrSyntax.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplSyntax) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrSyntax.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrNotAuthenticated when action is done without being authenticated first
type ErrNotAuthenticated = *ImplNotAuthenticated
type ImplNotAuthenticated struct {
	*errorCore
}

// NotAuthenticatedError creates a ErrNotAuthenticated error
func NotAuthenticatedError(msg ...interface{}) Error {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.Unauthenticated
	return &ImplNotAuthenticated{r}
}

// IsNull tells if the instance is null
func (e *ImplNotAuthenticated) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplNotAuthenticated) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrNotAuthenticated.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplNotAuthenticated) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrNotAuthenticated.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrForbidden when action is not allowed.
type ErrForbidden = *ImplForbidden
type ImplForbidden struct {
	*errorCore
}

// ForbiddenError creates a ErrForbidden error
func ForbiddenError(msg ...interface{}) Error {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.PermissionDenied
	return &ImplForbidden{r}
}

// IsNull tells if the instance is null
func (e *ImplForbidden) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplForbidden) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrForbidden.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplForbidden) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrForbidden.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrAborted ...
type ErrAborted = *ImplAborted
type ImplAborted struct {
	*errorCore
}

// AbortedError creates a ErrAborted error
func AbortedError(err error, msg ...interface{}) Error {
	var message string
	if len(msg) == 0 {
		message = "ImplAborted"
	} else {
		message = strprocess.FormatStrings(msg...)
	}
	r := newError(err, nil, message)
	r.grpcCode = codes.Aborted
	return &ImplAborted{r}
}

// IsNull tells if the instance is null
func (e *ImplAborted) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplAborted) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrAborted.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplAborted) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrAborted.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrOverflow is used when a limit is reached
type ErrOverflow = *ImplOverflow
type ImplOverflow struct {
	*errorCore
	limit uint
}

// OverflowError creates a ErrOverflow error
func OverflowError(err error, limit uint, msg ...interface{}) Error {
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
	return &ImplOverflow{
		errorCore: r,
		limit:     limit,
	}
}

// IsNull tells if the instance is null
func (e *ImplOverflow) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplOverflow) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrOverflow.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplOverflow) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of Oveflow.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrOverload when action cannot be honored because provider is overloaded (ie too many requests occured in a given time).
type ErrOverload = *ImplOverload
type ImplOverload struct {
	*errorCore
}

// OverloadError creates a ErrOverload error
func OverloadError(msg ...interface{}) Error {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.ResourceExhausted
	return &ImplOverload{r}
}

// IsNull tells if the instance is null
func (e *ImplOverload) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplOverload) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrOverload.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplOverload) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrOverload.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrNotImplemented ...
type ErrNotImplemented = *ImplNotImplemented
type ImplNotImplemented struct {
	*errorCore
}

// NotImplementedError creates a ErrNotImplemented report
func NotImplementedError(msg ...interface{}) Error {
	r := newError(nil, nil, debug.DecorateWithCallTrace("not implemented yet:", strprocess.FormatStrings(msg...), ""))
	r.grpcCode = codes.Unimplemented
	return &ImplNotImplemented{r}
}

// IsNull tells if the instance is null
func (e *ImplNotImplemented) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// NotImplementedErrorWithReason creates a ErrNotImplemented report
func NotImplementedErrorWithReason(what string, why string) Error {
	r := newError(nil, nil, debug.DecorateWithCallTrace("not implemented yet:", what, why))
	r.grpcCode = codes.Unimplemented
	return &ImplNotImplemented{r}
}

// AddConsequence ...
func (e *ImplNotImplemented) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrNotImplemented.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplNotImplemented) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrNotImplemented.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrRuntimePanic ...
type ErrRuntimePanic = *ImplRuntimePanic
type ImplRuntimePanic struct {
	*errorCore
}

// RuntimePanicError creates a ErrRuntimePanic error
func RuntimePanicError(msg ...interface{}) Error {
	r := newError(nil, nil, debug.DecorateWithCallTrace(strprocess.FormatStrings(msg...), "", ""))
	r.grpcCode = codes.Internal
	return &ImplRuntimePanic{r}
}

// IsNull tells if the instance is null
func (e *ImplRuntimePanic) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplRuntimePanic) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrRuntimePanic.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplRuntimePanic) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrRuntimePanic.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrInvalidInstance has to be used when a method is called from an instance equal to nil
type ErrInvalidInstance = *ImplInvalidInstance
type ImplInvalidInstance struct {
	*errorCore
}

// InvalidInstanceError creates a ErrInvalidInstance error
func InvalidInstanceError() Error {
	r := newError(nil, nil, debug.DecorateWithCallTrace("invalid instance:", "", "calling method from a nil pointer"))
	r.grpcCode = codes.FailedPrecondition
	return &ImplInvalidInstance{r}
}

// IsNull tells if the instance is null
func (e *ImplInvalidInstance) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplInvalidInstance) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrInvalidInstance.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplInvalidInstance) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrInvalidInstance.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrInvalidParameter ...
type ErrInvalidParameter = *ImplInvalidParameter
type ImplInvalidParameter struct {
	*errorCore
}

// InvalidParameterError creates a ErrInvalidParameter error
func InvalidParameterError(what, why string) Error {
	r := newError(nil, nil, debug.DecorateWithCallTrace("invalid parameter:", what, why))
	r.grpcCode = codes.FailedPrecondition
	return &ImplInvalidParameter{r}
}

// IsNull tells if the instance is null
func (e *ImplInvalidParameter) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplInvalidParameter) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrInvalidParameter.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplInvalidParameter) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrInvalidParameter.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrInvalidInstanceContent has to be used when a property of an instance contains invalid property
type ErrInvalidInstanceContent = *ImplInvalidInstanceContent
type ImplInvalidInstanceContent struct {
	*errorCore
}

// InvalidInstanceContentError returns an instance of ErrInvalidInstanceContent.
func InvalidInstanceContentError(what, why string) Error {
	r := newError(nil, nil, debug.DecorateWithCallTrace("invalid instance content:", what, why))
	r.grpcCode = codes.FailedPrecondition
	return &ImplInvalidInstanceContent{r}
}

// IsNull tells if the instance is null
func (e *ImplInvalidInstanceContent) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplInvalidInstanceContent) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrInvalidInstanceContent.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplInvalidInstanceContent) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrInvalidInstanceContent.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrInconsistent is used when data used is ImplInconsistent
type ErrInconsistent = *ImplInconsistent
type ImplInconsistent struct {
	*errorCore
}

// InconsistentError creates a ErrInconsistent error
func InconsistentError(msg ...interface{}) Error {
	r := newError(nil, nil, debug.DecorateWithCallTrace(strprocess.FormatStrings(msg...), "", ""))
	r.grpcCode = codes.DataLoss
	return &ImplInconsistent{r}
}

// IsNull tells if the instance is null
func (e *ImplInconsistent) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplInconsistent) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrInconsistent.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplInconsistent) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrInconsistent.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

// ErrExecution is used when code ImplExecution failed
type ErrExecution = *ImplExecution
type ImplExecution struct {
	*errorCore
}

// ExecutionError creates a ErrExecution error
func ExecutionError(exitError error, msg ...interface{}) Error {
	r := newError(nil, nil, msg...)
	r.grpcCode = codes.Internal

	retcode := int(-1)
	stderr := ""
	if ee, ok := exitError.(*exec.ExitError); ok {
		if status, ok := ee.Sys().(syscall.WaitStatus); ok {
			retcode = status.ExitStatus()
		}
		stderr = string(ee.Stderr)
	}
	_ = r.Annotate("retcode", retcode).Annotate("stderr", stderr)
	return &ImplExecution{errorCore: r}
}

// IsNull tells if the instance is null
func (e *ImplExecution) IsNull() bool {
	return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ImplExecution) AddConsequence(err error) Error {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrExecution.AddConsequence() from null instance")
		return e
	}
	_ = e.errorCore.AddConsequence(err)
	return e
}

// Annotate ...
func (e *ImplExecution) Annotate(key string, value data.Annotation) data.Annotatable {
	if e.IsNull() {
		logrus.Errorf("invalid call of ErrExecution.Annotate() from null instance")
		return e
	}
	_ = e.errorCore.Annotate(key, value)
	return e
}

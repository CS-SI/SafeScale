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

// consequencer is the interface exposing the methods manipulating consequences
type consequencer interface {
    Consequences() []error      // returns a slice of consequences
    AddConsequence(error) Error // adds a consequence to an error
}

// causer is the interface exposing the methods manipulating cause
type causer interface {
    CauseFormatter(func(Error) string) // defines a function used to format a causer output to string
    Cause() error                      // returns the first immediate cause of an error
    CauseError() string                // returns the cause of an error as an error
    RootCause() error                  // returns the root cause of an error
    RootCauseError() string            // returns the root cause of an error as string
}

// Error defines the interface of a SafeScale error
type Error interface {
    data.NullValue
    data.Annotatable
    causer
    consequencer
    error

    // Cause() error     // returns the first immediate cause of an error
    // RootCause() error // returns the root cause of an error

    // // ConsequenceFormatter(func(Error) string)
    // AddConsequence(err error) Error
    // Consequences() []error

    AnnotationFormatter(func(data.Annotations) string)

    ForceSetCause(error) Error   // set the cause of the error
    TrySetCause(error) bool // set the cause of the error if not already set

    // Error() string   // VPL: comes from error...

    GRPCCode() codes.Code
    ToGRPCStatus() error
}

// errorCore is the implementation of interface Error
type errorCore struct {
    message             string
    cause               error
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
        cause:        cause,
        consequences: consequences,
        annotations:  make(data.Annotations),
        grpcCode:     codes.Unknown,
    }
    r.causeFormatter = defaultCauseFormatter
    // r.consequenceFormatter = defaultConsequenceFormatter
    r.annotationFormatter = defaultAnnotationFormatter
    return &r
}

// IsNull tells if the instance is null
func (e *errorCore) IsNull() bool {
    return e == nil || (e.message == "" && e.cause == nil)
}

// defaultCauseFormatter generates a string containing information about the causing error and the derived errors while trying to clean up
func defaultCauseFormatter(e Error) string {
    if e.IsNull() {
        logrus.Errorf("invalid call of errorCore.CauseFormatter() from null instance")
        return ""
    }

    msgFinal := ""

    errCore := e.(*errorCore)
    if errCore.cause != nil {
        msgFinal += ": "
        msgFinal += errCore.cause.Error()
    }

    lenConseq := len(errCore.consequences)
    if lenConseq > 0 {
        msgFinal += "[with consequences {"
        for ind, con := range errCore.consequences {
            msgFinal += con.Error()
            if ind+1 < lenConseq {
                msgFinal += ";"
            }
        }
        msgFinal += "}]"
    }

    return msgFinal
}

// ForceSetCause sets the cause error even if already set
func (e *errorCore) ForceSetCause(err error) Error {
    if e.cause != nil {
        return e
    }
    e.cause = err
    return e
}

// TrySetCause sets the cause error if not already set
// Returns true if cause has been successfully set, false if cause was already set
func (e *errorCore) TrySetCause(err error) bool {
    if err == nil {
        return e.cause == nil
    }
    if e.cause != nil {
        return false
    }
    e.cause = err
    return true
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
func (e *errorCore) Cause() error {
    if e.IsNull() {
        logrus.Errorf("invalid call of errorCore.RootCause() from null instance")
        return nil
    }
    return Cause(e)
}

// CauseError returns the string of the error cause
// VPL: is it really necessary ? e.Cause().Error() does the job...
func (e *errorCore) CauseError() string {
    if !e.IsNull() {
        if e.cause != nil {
            return e.cause.Error()
        }
    }
    return ""
}

// RootCause returns the initial error's cause
func (e *errorCore) RootCause() error {
    if e.IsNull() {
        logrus.Errorf("invalid call of errorCore.RootCause() from null instance")
        return nil
    }
    return RootCause(e)
}

// RootCauseError returns the string corresponding to the root cause
// VPL: is it reallyt necessary ? e.RootCause().Error() does the job...
func (e *errorCore) RootCauseError() string {
    if !e.IsNull() {
        err := e.RootCause()
        if err != nil {
            return err.Error()
        }
    }
    return ""
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
func (e *errorCore) Annotations() data.Annotations {
    if e.IsNull() {
        logrus.Errorf("invalid call of errorCore.Annotations() from null instance")
        return nil
    }
    return e.annotations
}

// Annotation ...
func (e *errorCore) Annotation(key string) (data.Annotation, bool) {
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
func (e *errorCore) Consequences() []error {
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
func (e *errorCore) GRPCCode() codes.Code {
    if e.IsNull() {
        logrus.Errorf("invalid call of errorCore.GRPCCode() from null instance")
        return codes.Unknown
    }
    return e.grpcCode
}

// ToGRPCStatus returns a grpcstatus struct from error
func (e *errorCore) ToGRPCStatus() error {
    if e.IsNull() {
        logrus.Errorf("invalid call of errorCore.ToGRPCStatus() from null instance")
        return nil
    }
    return grpcstatus.Errorf(e.GRPCCode(), e.Error())
}

// ErrTimeout defines a ErrTimeout error
type ErrTimeout struct {
    *errorCore
    dur time.Duration
}

// TimeoutError returns an ErrTimeout instance
func TimeoutError(cause error, dur time.Duration, msg ...interface{}) *ErrTimeout {
    r := newError(cause, nil, msg...)
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
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrTimeout.AddConsequence() from null instance")
        return &ErrTimeout{}
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrTimeout) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrTimeout.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
    return e
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

// IsNull tells if the instance is null
func (e *ErrNotFound) IsNull() bool {
    return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrNotFound) AddConsequence(err error) Error {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrNotFound.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrNotFound) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrNotFound.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
    return e
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

// IsNull tells if the instance is null
func (e *ErrNotAvailable) IsNull() bool {
    return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrNotAvailable) AddConsequence(err error) Error {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrNotAvailable.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrNotAvailable) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrNotAvailable.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
    return e
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

// IsNull tells if the instance is null
func (e *ErrDuplicate) IsNull() bool {
    return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrDuplicate) AddConsequence(err error) Error {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrDuplicate.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
// satisfies interface data.Annotatable
func (e *ErrDuplicate) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrDuplicate.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
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
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrInvalidRequest.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate overloads errorCore.Annotate() to make sure the type returned is the same as the caller
// satisfies interface data.Annotatable
func (e *ErrInvalidRequest) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrInvalidRequest.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
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

// IsNull tells if the instance is null
func (e *ErrSyntax) IsNull() bool {
    return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrSyntax) AddConsequence(err error) Error {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrSyntax.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrSyntax) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrSyntax.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
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
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrNotAuthenticated.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrNotAuthenticated) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrNotAuthenticated.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
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
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrForbidden.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrForbidden) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrForbidden.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
    return e
}

// ErrAborted ...
type ErrAborted struct {
    *errorCore
}

// AbortedError creates a ErrAborted error
func AbortedError(err error, msg ...interface{}) *ErrAborted {
    var message string
    if len(msg) == 0 {
        message = "ErrAborted"
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
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrAborted.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrAborted) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrAborted.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
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
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrOverflow.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrOverflow) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of Oveflow.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
    return e
}

// ErrOverload when action cannot be honored because provider is overloaded (ie too many requests occured in a given time).
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
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrOverload.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrOverload) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrOverload.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
    return e
}

// ErrNotImplemented ...
type ErrNotImplemented struct {
    *errorCore
}

// NotImplementedError creates a ErrNotImplemented report
func NotImplementedError(msg ...interface{}) *ErrNotImplemented {
    r := newError(nil, nil, debug.DecorateWithCallTrace("not implemented yet:", strprocess.FormatStrings(msg...), ""))
    r.grpcCode = codes.Unimplemented
    return &ErrNotImplemented{r}
}

// IsNull tells if the instance is null
func (e *ErrNotImplemented) IsNull() bool {
    return e == nil || e.errorCore.IsNull()
}

// NotImplementedErrorWithReason creates a ErrNotImplemented report
func NotImplementedErrorWithReason(what string, why string) Error {
    r := newError(nil, nil, debug.DecorateWithCallTrace("not implemented yet:", what, why))
    r.grpcCode = codes.Unimplemented
    return &ErrNotImplemented{r}
}

// AddConsequence ...
func (e *ErrNotImplemented) AddConsequence(err error) Error {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrNotImplemented.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrNotImplemented) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrNotImplemented.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
    return e
}

// ErrRuntimePanic ...
type ErrRuntimePanic struct {
    *errorCore
}

// RuntimePanicError creates a ErrRuntimePanic error
func RuntimePanicError(msg ...interface{}) *ErrRuntimePanic {
    r := newError(nil, nil, debug.DecorateWithCallTrace(strprocess.FormatStrings(msg...), "", ""))
    r.grpcCode = codes.Internal
    return &ErrRuntimePanic{r}
}

// IsNull tells if the instance is null
func (e *ErrRuntimePanic) IsNull() bool {
    return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrRuntimePanic) AddConsequence(err error) Error {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrRuntimePanic.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrRuntimePanic) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrRuntimePanic.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
    return e
}

// ErrInvalidInstance has to be used when a method is called from an instance equal to nil
type ErrInvalidInstance struct {
    *errorCore
}

// InvalidInstanceError creates a ErrInvalidInstance error
func InvalidInstanceError() *ErrInvalidInstance {
    r := newError(nil, nil, debug.DecorateWithCallTrace("invalid instance:", "", "calling method from a nil pointer"))
    r.grpcCode = codes.FailedPrecondition
    return &ErrInvalidInstance{r}
}

// IsNull tells if the instance is null
func (e *ErrInvalidInstance) IsNull() bool {
    return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrInvalidInstance) AddConsequence(err error) Error {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrInvalidInstance.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrInvalidInstance) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrInvalidInstance.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
    return e
}

// ErrInvalidParameter ...
type ErrInvalidParameter struct {
    *errorCore
}

// InvalidParameterError creates a ErrInvalidParameter error
func InvalidParameterError(what, why string) *ErrInvalidParameter {
    r := newError(nil, nil, debug.DecorateWithCallTrace("invalid parameter:", what, why))
    r.grpcCode = codes.FailedPrecondition
    return &ErrInvalidParameter{r}
}

// IsNull tells if the instance is null
func (e *ErrInvalidParameter) IsNull() bool {
    return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrInvalidParameter) AddConsequence(err error) Error {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrInvalidParameter.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrInvalidParameter) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrInvalidParameter.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
    return e
}

// ErrInvalidInstanceContent has to be used when a property of an instance contains invalid property
type ErrInvalidInstanceContent struct {
    *errorCore
}

// InvalidInstanceContentError returns an instance of ErrInvalidInstanceContent.
func InvalidInstanceContentError(what, why string) *ErrInvalidInstanceContent {
    r := newError(nil, nil, debug.DecorateWithCallTrace("invalid instance content:", what, why))
    r.grpcCode = codes.FailedPrecondition
    return &ErrInvalidInstanceContent{r}
}

// IsNull tells if the instance is null
func (e *ErrInvalidInstanceContent) IsNull() bool {
    return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrInvalidInstanceContent) AddConsequence(err error) Error {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrInvalidInstanceContent.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrInvalidInstanceContent) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrInvalidInstanceContent.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
    return e
}

// ErrInconsistent is used when data used is ErrInconsistent
type ErrInconsistent struct {
    *errorCore
}

// InconsistentError creates a ErrInconsistent error
func InconsistentError(msg ...interface{}) *ErrInconsistent {
    r := newError(nil, nil, debug.DecorateWithCallTrace(strprocess.FormatStrings(msg...), "", ""))
    r.grpcCode = codes.DataLoss
    return &ErrInconsistent{r}
}

// IsNull tells if the instance is null
func (e *ErrInconsistent) IsNull() bool {
    return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrInconsistent) AddConsequence(err error) Error {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrInconsistent.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrInconsistent) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrInconsistent.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
    return e
}

// ErrExecution is used when code ErrExecution failed
type ErrExecution struct {
    *errorCore
}

// ExecutionError creates a ErrExecution error
func ExecutionError(exitError error, msg ...interface{}) *ErrExecution {
    r := newError(nil, nil, msg...)
    r.grpcCode = codes.Internal

    retcode := int(-1)
    stderr := ""
    if ee, ok := exitError.(*exec.ExitError); ok {
        if status, ok := ee.Sys().(syscall.WaitStatus); ok {
            retcode = status.ExitStatus()
        }
        stderr = string(ee.Stderr)
    } else {
        r.cause = exitError
    }
    _ = r.Annotate("retcode", retcode).Annotate("stderr", stderr)
    return &ErrExecution{errorCore: r}
}

// IsNull tells if the instance is null
func (e *ErrExecution) IsNull() bool {
    return e == nil || e.errorCore.IsNull()
}

// AddConsequence ...
func (e *ErrExecution) AddConsequence(err error) Error {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrExecution.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrExecution) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrExecution.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
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
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrUnknown.AddConsequence() from null instance")
        return e
    }
    _ = e.errorCore.AddConsequence(err)
    return e
}

// Annotate ...
func (e *ErrUnknown) Annotate(key string, value data.Annotation) data.Annotatable {
    if e.IsNull() {
        logrus.Errorf("invalid call of ErrUnknown.Annotate() from null instance")
        return e
    }
    _ = e.errorCore.Annotate(key, value)
    return e
}
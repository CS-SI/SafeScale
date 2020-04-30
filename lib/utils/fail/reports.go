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

	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
)

// Report defines the interface of a SafeScale error
type Report interface {
	IsNull() bool
	AddConsequence(err error) Report
	WithField(key string, value interface{}) Report
	Cause() error
	CauseFormatter() string
	Consequences() []error
	Fields() map[string]interface{}
	Error() string
	FieldsFormatter() string
	GRPCCode() codes.Code
	ToGRPCStatus() error
}

type fields map[string]interface{}

// reportCore is the implementation of interface Report
type reportCore struct {
	message      string
	causer       error
	fields       fields
	consequences []error
	grpcCode     codes.Code
}

// NewReport creates a new failure report
func NewReport(msg ...interface{}) Report {
	return newReport(nil, nil, msg...)
}

// NewReportWithCause creates a new failure report with a cause
func NewReportWithCause(cause error, msg ...interface{}) Report {
	return newReport(cause, nil, msg...)
}

// NewReportWithCauseAndConsequences creates a new failure report with a cause and a list of teardown problems 'consequences'
func NewReportWithCauseAndConsequences(cause error, consequences []error, msg ...interface{}) Report {
	return newReport(cause, consequences, msg...)
}

// newReport creates a new failure report with a message 'message', a causer error 'causer' and a list of teardown problems 'consequences'
func newReport(cause error, consequences []error, msg ...interface{}) Report {
	if consequences == nil {
		consequences = []error{}
	}
	return &reportCore{
		message:      strprocess.FormatStrings(msg...),
		causer:       cause,
		consequences: consequences,
		fields:       make(fields),
		grpcCode:     codes.Unknown,
	}
}

func nullReport() Report {
	return &reportCore{}
}

// IsNull tells if the instance is null
func (e *reportCore) IsNull() bool {
	return e == nil || e.message == ""
}

// FieldsFormatter ...
func (e *reportCore) FieldsFormatter() string {
	if e.IsNull() {
		logrus.Errorf("invalid call of reportCore.FieldsFormatter() from null instance")
		return ""
	}
	j, err := json.Marshal(e.fields)

	if err != nil {
		return ""
	}

	return string(j)
}

// CauseFormatter generates a string containing information about the causing error and the derived errors while trying to clean up
func (e *reportCore) CauseFormatter() string {
	if e.IsNull() {
		logrus.Errorf("invalid call of reportCore.CauseFormatter() from null instance")
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

// Reset imports content of error err to receiving error e
func (e *reportCore) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of reportCore.Reset() from null instance")
		return nullReport()
	}
	if err != nil {
		if cerr, ok := err.(*reportCore); ok {
			e.message = cerr.message
			e.consequences = cerr.consequences
			e.causer = cerr.causer
		}
	}
	return e
}

// Cause returns an error's cause
func (e *reportCore) Cause() error {
	if e.IsNull() {
		logrus.Errorf("invalid call of reportCore.Cause() from null instance")
		return nil
	}
	return e.causer
}

// Consequences returns the consequences of current error (detected teardown problems)
func (e *reportCore) Consequences() []error {
	if e.IsNull() {
		logrus.Errorf("invalid call of reportCore.Consequences() from null instance")
		return nil
	}
	return e.consequences
}

// Fields ...
func (e *reportCore) Fields() map[string]interface{} {
	if e.IsNull() {
		logrus.Errorf("invalid call of reportCore.Fields() from null instance")
		return nil
	}
	return e.fields
}

// GRPCCode returns the appropriate error code to use with gRPC
func (e *reportCore) GRPCCode() codes.Code {
	if e.IsNull() {
		logrus.Errorf("invalid call of reportCore.GRPCCode() from null instance")
		return codes.Unknown
	}
	return e.grpcCode
}

// ToGRPCStatus returns a grpcstatus struct from error
func (e *reportCore) ToGRPCStatus() error {
	if e.IsNull() {
		logrus.Errorf("invalid call of reportCore.ToGRPCStatus() from null instance")
		return nil
	}
	return grpcstatus.Errorf(e.GRPCCode(), e.Error())
}

// AddConsequence ...
// AddConsequence adds an error 'err' to the list of consequences
func (e *reportCore) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of reportCore.AddConsequence() from null instance")
		return nullReport()
	}
	if err != nil {
		if e.consequences == nil {
			e.consequences = []error{}
		}
		e.consequences = append(e.consequences, err)
	}
	return e
}

// WithField ...
func (e *reportCore) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of reportCore.WithField() from null instance")
		return nullReport()
	}

	if e.fields != nil {
		e.fields[key] = value
	}

	return e
}

// Report returns a human-friendly error explanation
func (e *reportCore) Error() string {
	if e.IsNull() {
		logrus.Errorf("invalid call of reportCore.Error() from null instance")
		return ""
	}

	msgFinal := e.message

	msgFinal += e.CauseFormatter()

	if len(e.fields) > 0 {
		msgFinal += "\nWith fields: "
		msgFinal += e.FieldsFormatter()
	}

	return msgFinal
}

// Timeout defines a Timeout error
type Timeout = *timeout
type timeout struct {
	*reportCore
	dur time.Duration
}

// TimeoutReport returns an Timeout instance
func TimeoutReport(cause error, dur time.Duration, msg ...interface{}) *timeout {
	return &timeout{
		reportCore: &reportCore{
			message:      strprocess.FormatStrings(msg...),
			causer:       cause,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.DeadlineExceeded,
		},
		dur: dur,
	}
}

// AddConsequence ...
func (e *timeout) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Timeout.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *timeout) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Timeout.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *timeout) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Timeout.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// NotFound resource not found error
type NotFound = *notFound
type notFound struct {
	*reportCore
}

// NotFoundReport creates a NotFound error
func NotFoundReport(msg ...interface{}) *notFound {
	return &notFound{
		reportCore: &reportCore{
			message:      strprocess.FormatStrings(msg...),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.NotFound,
		},
	}
}

// AddConsequence ...
func (e *notFound) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of NotFound.AddConsequence() from null instance")
		return nullReport()
	}

	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *notFound) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of NotFound.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *notFound) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of NotFound.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// NotAvailable resource not available error
type NotAvailable = *notAvailable
type notAvailable struct {
	*reportCore
}

// NotAvailableReport creates a NotAvailable error
func NotAvailableReport(msg ...interface{}) *notAvailable {
	return &notAvailable{
		reportCore: &reportCore{
			message:      strprocess.FormatStrings(msg...),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.Unavailable,
		},
	}
}

// AddConsequence ...
func (e *notAvailable) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of NotAvailable.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *notAvailable) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of NotAvailable.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *notAvailable) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of NotAvailable.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// Duplicate already exists error
type Duplicate = *duplicate
type duplicate struct {
	*reportCore
}

// DuplicateReport creates a Duplicate error
func DuplicateReport(msg ...interface{}) Duplicate {
	return &duplicate{
		reportCore: &reportCore{
			message:      strprocess.FormatStrings(msg...),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.AlreadyExists,
		},
	}
}

// AddConsequence ...
func (e *duplicate) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Duplicate.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *duplicate) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Duplicate.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *duplicate) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Duplicate.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// InvalidRequest ...
type InvalidRequest = *invalidRequest
type invalidRequest struct {
	*reportCore
}

// InvalidRequestReport creates a InvalidRequest error
func InvalidRequestReport(msg ...interface{}) InvalidRequest {
	return &invalidRequest{
		reportCore: &reportCore{
			message:      strprocess.FormatStrings(msg...),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.InvalidArgument,
		},
	}
}

// AddConsequence ...
func (e *invalidRequest) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of InvalidRequest.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *invalidRequest) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of InvalidRequest.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *invalidRequest) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of InvalidRequest.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// Syntax ...
type Syntax = *syntax
type syntax struct {
	*reportCore
}

// SyntaxReport creates a Syntax error
func SyntaxReport(msg ...interface{}) Syntax {
	return &syntax{
		reportCore: &reportCore{
			message:      strprocess.FormatStrings(msg...),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.Internal,
		},
	}
}

// AddConsequence ...
func (e *syntax) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Syntax.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *syntax) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Syntax.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *syntax) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Syntax.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// NotAuthenticated when action is done without being authenticated first
type NotAuthenticated = *notAuthenticated
type notAuthenticated struct {
	*reportCore
}

// NotAuthenticatedReport creates a NotAuthenticated error
func NotAuthenticatedReport(msg ...interface{}) NotAuthenticated {
	return &notAuthenticated{
		reportCore: &reportCore{
			message:      strprocess.FormatStrings(msg...),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.Unauthenticated,
		},
	}
}

// AddConsequence ...
func (e *notAuthenticated) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of NotAuthenticated.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *notAuthenticated) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of NotAuthenticated.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *notAuthenticated) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of NotAuthenticated.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// Forbidden when action is not allowed.
type Forbidden = *forbidden
type forbidden struct {
	*reportCore
}

// ForbiddenReport creates a Forbidden error
func ForbiddenReport(msg ...interface{}) *forbidden {
	return &forbidden{
		reportCore: &reportCore{
			message:      strprocess.FormatStrings(msg...),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.PermissionDenied,
		},
	}
}

// AddConsequence ...
func (e *forbidden) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Forbidden.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *forbidden) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Forbidden.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *forbidden) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Forbidden.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// Aborted ...
type Aborted = *aborted
type aborted struct {
	*reportCore
}

// AbortedReport creates a Aborted error
func AbortedReport(err error, msg ...interface{}) Report {
	var message string
	if len(msg) == 0 {
		message = "aborted"
	} else {
		message = strprocess.FormatStrings(msg...)
	}
	return &aborted{
		reportCore: &reportCore{
			message:      message,
			causer:       err,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.Aborted,
		},
	}
}

// AddConsequence ...
func (e *aborted) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Aborted.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *aborted) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Aborted.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *aborted) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Aborted.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// Overflow is used when a limit is reached
type Overflow = *overflow
type overflow struct {
	*reportCore
	limit uint
}

// OverflowReport creates a Overflow error
func OverflowReport(err error, limit uint, msg ...interface{}) *overflow {
	message := strprocess.FormatStrings(msg...)
	if limit > 0 {
		limitMsg := fmt.Sprintf("(limit: %d)", limit)
		if message != "" {
			message += " "
		}
		message += limitMsg
	}
	return &overflow{
		reportCore: &reportCore{
			message:      message,
			causer:       err,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.OutOfRange,
		},
		limit: limit,
	}
}

// AddConsequence ...
func (e *overflow) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Overflow.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *overflow) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Oveflow.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *overflow) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Overflow.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// Overload when action cannot be honored because provider is overloaded (ie too many requests occured in a given time).
type Overload = *overload
type overload struct {
	*reportCore
}

// OverloadReport creates a Overload error
func OverloadReport(msg ...interface{}) Overload {
	return &overload{
		reportCore: &reportCore{
			message:      strprocess.FormatStrings(msg...),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.ResourceExhausted,
		},
	}
}

// AddConsequence ...
func (e *overload) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Overload.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *overload) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Overload.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *overload) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Overload.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// NotImplemented ...
type NotImplemented = *notImplemented
type notImplemented struct {
	*reportCore
}

// NotImplementedReport creates a NotImplemented error
func NotImplementedReport(msg ...interface{}) *notImplemented {
	return &notImplemented{
		reportCore: &reportCore{
			message:      decorateWithCallTrace("not implemented yet:", strprocess.FormatStrings(msg...), ""),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.Unimplemented,
		},
	}
}

// AddConsequence ...
func (e *notImplemented) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of NotImplemented.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *notImplemented) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of NotImplemented.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *notImplemented) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of NotImplemented.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// NotImplementedReportWithReason creates a NotImplemented error
func NotImplementedReportWithReason(what string, why string) *notImplemented {
	return &notImplemented{
		reportCore: &reportCore{
			message:      decorateWithCallTrace("not implemented yet:", what, why),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.Unimplemented,
		},
	}
}

// RuntimePanic ...
type RuntimePanic = *runtimePanic
type runtimePanic struct {
	*reportCore
}

// RuntimePanicReport creates a RuntimePanic error
func RuntimePanicReport(msg ...interface{}) *runtimePanic {
	return &runtimePanic{
		reportCore: &reportCore{
			message:      decorateWithCallTrace(strprocess.FormatStrings(msg...), "", ""),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.Internal,
		},
	}
}

// AddConsequence ...
func (e *runtimePanic) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of RuntimePanic.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *runtimePanic) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of RuntimePanic.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *runtimePanic) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of RuntimePanic.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// InvalidInstance has to be used when a method is called from an instance equal to nil
type InvalidInstance = *invalidInstance
type invalidInstance struct {
	*reportCore
}

// InvalidInstanceReport creates a InvalidInstance error
func InvalidInstanceReport() *invalidInstance {
	return &invalidInstance{
		reportCore: &reportCore{
			message:      decorateWithCallTrace("invalid instance:", "", "calling method from a nil pointer"),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.FailedPrecondition,
		},
	}
}

// AddConsequence ...
func (e *invalidInstance) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of InvalidInstance.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *invalidInstance) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of InvalidInstance.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *invalidInstance) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of InvalidInstance.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// InvalidParameter ...
type InvalidParameter = *invalidParameter
type invalidParameter struct {
	*reportCore
}

// InvalidParameterReport creates a InvalidParameter error
func InvalidParameterReport(what, why string) *invalidParameter {
	return &invalidParameter{
		reportCore: &reportCore{
			message:      decorateWithCallTrace("invalid parameter:", what, why),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.FailedPrecondition,
		},
	}
}

// AddConsequence ...
func (e *invalidParameter) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of InvalidParameter.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *invalidParameter) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of InvalidParameter.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *invalidParameter) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of InvalidParameter.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// InvalidInstanceContent has to be used when a property of an instance contains invalid property
type InvalidInstanceContent = *invalidInstanceContent
type invalidInstanceContent struct {
	*reportCore
}

// InvalidInstanceContentReport returns an instance of InvalidInstanceContent.
func InvalidInstanceContentReport(what, why string) *invalidInstanceContent {
	return &invalidInstanceContent{
		reportCore: &reportCore{
			message:      decorateWithCallTrace("invalid instance content:", what, why),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.FailedPrecondition,
		},
	}
}

// AddConsequence ...
func (e *invalidInstanceContent) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of InvalidInstanceContent.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *invalidInstanceContent) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of InvalidInstanceContent.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *invalidInstanceContent) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of InvalidInstanceContent.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

// Inconsistent is used when data used is inconsistent
type Inconsistent = *inconsistent
type inconsistent struct {
	*reportCore
}

// InconsistentReport creates a Inconsistent error
func InconsistentReport(msg ...interface{}) *inconsistent {
	return &inconsistent{
		reportCore: &reportCore{
			message:      decorateWithCallTrace(strprocess.FormatStrings(msg...), "", ""),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.DataLoss,
		},
	}
}

// AddConsequence ...
func (e *inconsistent) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Inconsistent.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *inconsistent) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Inconsistent.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Execution is used when code execution failed
type Execution = *execution
type execution struct {
	*reportCore
}

// ExecutionReport creates a Execution error
func ExecutionReport(exitError error, msg ...interface{}) *execution {
	e := &execution{
		reportCore: &reportCore{
			message:      strprocess.FormatStrings(msg...),
			causer:       nil,
			consequences: []error{},
			fields:       make(fields),
			grpcCode:     codes.Internal,
		},
	}

	retcode := int(-1)
	stderr := ""
	if ee, ok := exitError.(*exec.ExitError); ok {
		if status, ok := ee.Sys().(syscall.WaitStatus); ok {
			retcode = status.ExitStatus()
		}
		stderr = string(ee.Stderr)
	}
	_ = e.WithField("retcode", retcode).WithField("stderr", stderr)
	return e
}

// AddConsequence ...
func (e *execution) AddConsequence(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Execution.AddConsequence() from null instance")
		return nullReport()
	}
	_ = e.reportCore.AddConsequence(err)
	return e
}

// WithField ...
func (e *execution) WithField(key string, value interface{}) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Execution.WithField() from null instance")
		return nullReport()
	}
	_ = e.reportCore.WithField(key, value)
	return e
}

// Reset ...
func (e *execution) Reset(err error) Report {
	if e.IsNull() {
		logrus.Errorf("invalid call of Execution.Reset() from null instance")
		return nullReport()
	}
	_ = e.reportCore.Reset(err)
	return e
}

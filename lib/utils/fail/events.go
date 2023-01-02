/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/v22/lib/utils/commonlog"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

const (
	outputErrorTemplate = "%s: %+v"
)

// OnExitLogErrorWithLevel logs error with the log level wanted
func OnExitLogErrorWithLevel(ctx context.Context, err interface{}, level logrus.Level, msg ...interface{}) {
	if err != nil {
		logLevelFn := commonlog.LogLevelFnMap(ctx, level)

		switch v := err.(type) {
		case *ErrRuntimePanic, *ErrInvalidInstance, *ErrInvalidInstanceContent, *ErrInvalidParameter:
			// These errors are systematically logged, no need to log them twice
		case *Error:
			if *v != nil {
				logLevelFn(fmt.Sprintf(outputErrorTemplate, consolidateMessage(msg...), *v))
			}
		case *error:
			if *v != nil {
				if IsGRPCError(*v) {
					logLevelFn(fmt.Sprintf(outputErrorTemplate, consolidateMessage(msg...), grpcstatus.Convert(*v).Message()))
				} else {
					logLevelFn(fmt.Sprintf(outputErrorTemplate, consolidateMessage(msg...), *v))
				}
			}
		default:
			logrus.WithContext(ctx).Errorf(callstack.DecorateWith("fail.OnExitLogErrorWithLevel(): ", "invalid parameter 'err'", fmt.Sprintf("unexpected type '%s'", reflect.TypeOf(err).String()), 5))
		}
	}
}

func consolidateMessage(msg ...interface{}) string {
	out := strprocess.FormatStrings(msg)
	if len(out) == 0 {
		out = extractCallerName()
	}
	return out
}

func extractCallerName() string {
	// if 'in' is empty, recover function name from caller
	var out string
	toSkip := 3 // skip 3 first calls, being something + consolidateMessage + extractCallerName...
	for {
		if pc, file, line, ok := runtime.Caller(toSkip); ok {
			if f := runtime.FuncForPC(pc); f != nil {
				if strings.Contains(f.Name(), "fail.OnExit") {
					toSkip++
					continue
				}
				out = filepath.Base(f.Name()) + fmt.Sprintf("() [%s:%d]", callstack.SourceFilePathUpdater()(file), line)
				break
			}
		}

		if toSkip >= 6 { // Unlikely to reach this point
			break
		}
	}
	return out
}

// OnExitLogError logs error with level logrus.ErrorLevel.
// func OnExitLogError(in string, err *error) {
func OnExitLogError(ctx context.Context, err interface{}, msg ...interface{}) {
	OnExitLogErrorWithLevel(ctx, err, logrus.ErrorLevel, msg...)
}

// OnExitWrapError wraps the error with the message
func OnExitWrapError(ctx context.Context, err interface{}, msg ...interface{}) {
	if err != nil {
		var newErr error
		switch v := err.(type) {
		case *Error:
			if *v != nil {
				newErr = Wrap(*v, msg...)
			}
		case *error:
			if *v != nil {
				newErr = Wrap(*v, msg...)
			}
		default:
			logrus.WithContext(ctx).Errorf(callstack.DecorateWith("fail.OnExitWrapError()", "invalid parameter 'err'", fmt.Sprintf("unexpected type '%s'", reflect.TypeOf(err).String()), 0))
			return
		}
		if newErr != nil {
			targetErr, ok := err.(*error)
			if ok {
				*targetErr = newErr
			} else {
				logrus.WithContext(ctx).Errorf("This is a coding mistake, OnExitWrapError only works when 'err' is a '*error'")
				return
			}
		}
	}
}

// OnExitConvertToGRPCStatus converts err to GRPC Status.
func OnExitConvertToGRPCStatus(ctx context.Context, err *error) {
	if err != nil && *err != nil {
		var newErr error
		switch v := (*err).(type) {
		case Error:
			newErr = v.ToGRPCStatus()
		case error:
			newErr = ToGRPCStatus(v)
		default:
			logrus.WithContext(ctx).Errorf("fail.OnExitConvertToGRPCStatus(): invalid parameter 'err': unexpected type '%s'", reflect.TypeOf(err).String())
			return
		}
		if newErr != nil {
			*err = newErr
		}
	}
}

// OnExitTraceError logs error with level logrus.TraceLevel.
// func OnExitTraceError(in string, err *error) {
func OnExitTraceError(ctx context.Context, err interface{}, msg ...interface{}) {
	OnExitLogErrorWithLevel(ctx, err, logrus.TraceLevel, msg...)
}

// OnPanic captures panic error and fill the error pointer with a ErrRuntimePanic.
func OnPanic(err interface{}) {
	logCall := getEventLogger()

	if x := recover(); x != nil {
		switch v := err.(type) {
		case *ErrorList:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrUnqualified:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrWarning:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrTimeout:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrNotFound:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrAborted:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrRuntimePanic:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrNotAvailable:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrDuplicate:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrInvalidRequest:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrSyntax:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrNotAuthenticated:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrForbidden:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrOverflow:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrOverload:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrNotImplemented:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrInvalidInstance:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrInvalidParameter:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrInvalidInstanceContent:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrInconsistent:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrExecution:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrAlteredNothing:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrUnknown:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *Error:
			if v != nil {
				recTrace := callstack.IgnoreTraceUntil(x, "src/runtime/panic", callstack.LastOccurrence)
				*v = RuntimePanicError("runtime panic occurred:\n%s", recTrace)
			} else {
				logCall(callstack.DecorateWith("fail.OnPanic()", "intercepted panic but '*err' is nil", "", 4))
			}
		case *error:
			if v != nil {
				*v = RuntimePanicError("runtime panic occurred: %+v", x)
			} else {
				logCall(callstack.DecorateWith("fail.OnPanic()", "intercepted panic but '*err' is nil", "", 4))
			}
		default:
			logCall(callstack.DecorateWith("fail.OnPanic()", "intercepted panic but parameter 'err' is invalid", fmt.Sprintf("unexpected type '%s'", reflect.TypeOf(err).String()), 4))
		}
	}
}

// SilentOnPanic captures panic error and logs the error, is intended for functions that DON'T return errors
func SilentOnPanic(err interface{}) {
	logCall := getEventLogger()

	if x := recover(); x != nil {
		switch v := err.(type) {
		case *ErrorList:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrUnqualified:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrWarning:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrTimeout:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrNotFound:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrAborted:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrRuntimePanic:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrNotAvailable:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrDuplicate:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrInvalidRequest:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrSyntax:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrNotAuthenticated:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrForbidden:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrOverflow:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrOverload:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrNotImplemented:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrInvalidInstance:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrInvalidParameter:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrInvalidInstanceContent:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrInconsistent:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrExecution:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrAlteredNothing:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *ErrUnknown:
			logCall(callstack.DecorateWith("fail.OnPanic()", "coding mistake", "functions that can panic MUST NOT return *fail.Whatever, only fail.Error", 4))
		case *Error:
			if v != nil {
				recTrace := callstack.IgnoreTraceUntil(x, "src/runtime/panic", callstack.LastOccurrence)
				*v = RuntimePanicError("runtime panic occurred:\n%s", recTrace)
				logCall("%s", RuntimePanicError("runtime panic occurred:\n%s", recTrace))
			} else {
				logCall(callstack.DecorateWith("fail.OnPanic()", "intercepted panic but '*err' is nil", "", 4))
			}
		case *error:
			if v != nil {
				*v = RuntimePanicError("runtime panic occurred: %+v", x)
				logCall("%s", RuntimePanicError("runtime panic occurred: %+v", x))
			} else {
				logCall(callstack.DecorateWith("fail.OnPanic()", "intercepted panic but '*err' is nil", "", 4))
			}
		default:
			logCall(callstack.DecorateWith("fail.OnPanic()", "intercepted panic but parameter 'err' is invalid", fmt.Sprintf("unexpected type '%s'", reflect.TypeOf(err).String()), 4))
		}
	}
}

func IgnoreProblems(_ interface{}) {
	if x := recover(); x != nil { // nolint
		// nothing to do
	}
}

/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/lib/utils/commonlog"
	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
)

const (
	// errorOccurred       = "ERROR OCCURRED"
	// outputErrorTemplate = "%s " + errorOccurred + ": %+v"
	outputErrorTemplate = "%s: %+v"
)

// OnExitLogErrorWithLevel logs error with the log level wanted
func OnExitLogErrorWithLevel(err interface{}, level logrus.Level, msg ...interface{}) {
	if err == nil {
		return
	}

	logLevelFn, ok := commonlog.LogLevelFnMap[level]
	if !ok {
		logLevelFn = logrus.Error
	}

	in := strprocess.FormatStrings(msg)
	if len(in) == 0 {
		in = extractCallerName()
	}

	switch v := err.(type) {
	case *ErrRuntimePanic, *ErrInvalidInstance, *ErrInvalidInstanceContent, *ErrInvalidParameter:
		// These errors are systematically logged, no need to log them twice
	case *Error:
		if *v != nil {
			logLevelFn(fmt.Sprintf(outputErrorTemplate, in, *v))
		}
	case *error:
		if *v != nil {
			if IsGRPCError(*v) {
				logLevelFn(fmt.Sprintf(outputErrorTemplate, in, grpcstatus.Convert(*v).Message()))
			} else {
				logLevelFn(fmt.Sprintf(outputErrorTemplate, in, *v))
			}
		}
	default:
		logrus.Errorf(callstack.DecorateWith("fail.OnExitLogErrorWithLevel()", "invalid parameter 'err'", fmt.Sprintf("unexpected type '%s'", reflect.TypeOf(err).String()), 5))
	}
}

func extractCallerName() string {
	// if 'in' is empty, recover function name from caller
	var out string
	toSkip := 0
	for {
		if pc, _, line, ok := runtime.Caller(toSkip); ok {
			if f := runtime.FuncForPC(pc); f != nil {
				if strings.Contains(f.Name(), "fail.OnExitLog") || strings.Contains(f.Name(), "fail.extractCallerName") {
					toSkip++
					continue
				}
				out = filepath.Base(f.Name() + fmt.Sprintf(",%d", line))
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
func OnExitLogError(err interface{}, msg ...interface{}) {
	OnExitLogErrorWithLevel(err, logrus.ErrorLevel, msg...)
}

// OnExitWrapError wraps the error with the message
func OnExitWrapError(err interface{}, msg ...interface{}) {
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
			logrus.Errorf("fail.OnExitWrapError(): invalid parameter 'err': unexpected type '%s'", reflect.TypeOf(err).String())
			return
		}
		if newErr != nil {
			targetErr := err.(*error)
			*targetErr = newErr
		}
	}
}

// OnExitConvertToGRPCStatus converts err to GRPC Status.
func OnExitConvertToGRPCStatus(err interface{}) {
	if err != nil {
		var newErr error
		switch v := err.(type) {
		case *Error:
			if *v != nil {
				newErr = (*v).ToGRPCStatus()
			}
		case *error:
			if *v != nil {
				newErr = ToGRPCStatus(*v)
			}
		default:
			logrus.Errorf("fail.OnExitConvertToGRPCStatus(): invalid parameter 'err': unexpected type '%s'", reflect.TypeOf(err).String())
			return
		}
		if newErr != nil {
			targetErr := err.(*error)
			*targetErr = newErr
		}
	}
}

// OnExitTraceError logs error with level logrus.TraceLevel.
// func OnExitTraceError(in string, err *error) {
func OnExitTraceError(err interface{}, msg ...interface{}) {
	OnExitLogErrorWithLevel(err, logrus.TraceLevel, msg...)
}

// OnPanic captures panic error and fill the error pointer with a ErrRuntimePanic.
// func OnPanic(err *error) {
func OnPanic(err interface{}) {
	if x := recover(); x != nil {
		switch v := err.(type) {
		case *Error:
			if v != nil {
				*v = RuntimePanicError("runtime panic occurred:\n%s", callstack.IgnoreTraceUntil(x, "src/runtime/panic", callstack.FirstOccurence))
			} else {
				logrus.Errorf(callstack.DecorateWith("fail.OnPanic()", " intercepted panic but '*err' is nil", "", 5))
			}
		case *error:
			if v != nil {
				*v = RuntimePanicError("runtime panic occurred: %+v", x)
			} else {
				logrus.Errorf(callstack.DecorateWith("fail.OnPanic()", " intercepted panic but '*err' is nil", "", 5))
			}
		default:
			logrus.Errorf(callstack.DecorateWith("fail.OnPanic()", " intercepted panic but parameter 'err' is invalid", fmt.Sprintf("unexpected type '%s'", reflect.TypeOf(err).String()), 5))
		}
	}
}

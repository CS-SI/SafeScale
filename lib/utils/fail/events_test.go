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
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/tests"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func createErrorCore(message string) *errorCore {
	return &errorCore{
		message:             message,
		cause:               nil,
		consequences:        []error{},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
}

func Test_OnExitLogErrorWithLevel(t *testing.T) {

	log := tests.LogrusCapture(func() {
		OnExitLogErrorWithLevel(context.Background(), nil, logrus.WarnLevel)
	})
	require.EqualValues(t, log, "")

	log = tests.LogrusCapture(func() {
		OnExitLogErrorWithLevel(context.Background(), struct{}{}, logrus.WarnLevel)
	})
	require.Contains(t, log, "fail.OnExitLogErrorWithLevel()")

	log = tests.LogrusCapture(func() {
		nerr := errors.New("Any message")
		OnExitLogErrorWithLevel(context.Background(), &nerr, logrus.WarnLevel)
	})
	require.Contains(t, log, "Any message")

	log = tests.LogrusCapture(func() {
		nerr := grpcstatus.Error(codes.FailedPrecondition, "GRPC Error: id was not found")
		OnExitLogErrorWithLevel(context.Background(), &nerr, logrus.WarnLevel)

		fmt.Println(nerr)
	})
	require.Contains(t, log, "GRPC Error")
	require.Contains(t, log, "FailedPrecondition")

	errs := []Error{
		WarningError(errors.New("math: can't divide by zero"), "Any message"),
		TimeoutError(errors.New("math: can't divide by zero"), 30*time.Second, "Any message"),
		AbortedError(errors.New("math: can't divide by zero"), "Any message"),
		OverflowError(errors.New("math: can't divide by zero"), 30, "Any message"),
		ExecutionError(errors.New("exit error"), "Any message"),
		NewError("Any message"),
		&errorCore{
			message:             "math: can't divide by zero: Any message",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}

	for i := range errs {
		log = tests.LogrusCapture(func() {
			err := func(in_err Error) (out_err error) {
				defer OnExitLogErrorWithLevel(context.Background(), &in_err, logrus.WarnLevel)
				return in_err
			}(errs[i])
			if err == nil {
				t.Fail()
			}

		})
		if !strings.Contains(log, "level=warning") {
			t.Errorf("Invalid '%s' log level", reflect.TypeOf(errs[i]).String())
			t.Fail()
		}
		if !strings.Contains(log, "Any message") {
			t.Errorf("Invalid '%s' error message", errs[i].Error())
			t.Fail()
		}
	}

}

func OnExit_extractCallerName_deepcall(length uint, callback func() string) string {
	if length > 0 {
		length--
		OnExit_extractCallerName_deepcall(length, callback)
	}
	return callback()
}

func thingThatPanics() (ferr Error) {
	defer func() {
		if ferr != nil {
			ctx := context.WithValue(context.Background(), "ID", "afraid")
			ferr.WithContext(ctx)
		}
	}()
	defer OnPanic(&ferr)

	panic("whoa")
}

func TestContextWithPanic(t *testing.T) {
	xerr := thingThatPanics()
	require.NotNil(t, xerr)
	require.Contains(t, xerr.Error(), "afraid")
}

func Test_extractCallerName(t *testing.T) {

	result := extractCallerName()
	require.Contains(t, result, "runtime.goexit")

	result = func() string { // nolint
		return extractCallerName() // nolint
	}()
	require.Contains(t, result, "testing.tRunner")

	result = func() string { // nolint
		return func() string { // nolint
			return extractCallerName() // nolint
		}()
	}()
	require.Contains(t, result, "fail.Test_extractCallerName")

	result = func() string { // nolint
		return func() string { // nolint
			return func() string { // nolint
				return extractCallerName() // nolint
			}()
		}()
	}()
	require.Contains(t, result, "fail.Test_extractCallerName")

	result = func() string {
		return func() string {
			return func() string {
				return func() string { // nolint
					return extractCallerName() // nolint
				}()
			}()
		}()
	}()
	require.Contains(t, result, "fail.Test_extractCallerName")

	result = func() string {
		return func() string {
			return func() string {
				return func() string {
					return func() string { // nolint
						return extractCallerName() // nolint
					}()
				}()
			}()
		}()
	}()
	require.Contains(t, result, "fail.Test_extractCallerName")

	result = OnExit_extractCallerName_deepcall(12, extractCallerName)
	require.Contains(t, result, "testing.tRunner")

}

func Test_OnExitLogError(t *testing.T) {

	log := tests.LogrusCapture(func() {
		OnExitLogError(context.Background(), nil, "test")
	})
	require.EqualValues(t, log, "")

	log = tests.LogrusCapture(func() {
		nerr := fmt.Errorf("Any message")
		OnExitLogError(context.Background(), &nerr, "test")
	})
	if !strings.Contains(log, "Any message") {
		t.Fail()
	}

	errs := []Error{
		WarningError(errors.New("math: can't divide by zero"), "Any message"),
		TimeoutError(errors.New("math: can't divide by zero"), 30*time.Second, "Any message"),
		AbortedError(errors.New("math: can't divide by zero"), "Any message"),
		OverflowError(errors.New("math: can't divide by zero"), 30, "Any message"),
		ExecutionError(errors.New("exit error"), "Any message"),
		NewError("Any message"),
	}

	for i := range errs {
		log = tests.LogrusCapture(func() {
			err := func(in_err Error) (out_err error) {
				defer OnExitLogError(context.Background(), &in_err, "test")
				return in_err
			}(errs[i])
			if err == nil {
				t.Fail()
			}

		})
		if !strings.Contains(log, "level=error") {
			t.Fail()
		}
		if !strings.Contains(log, "Any message") {
			t.Fail()
		}
	}

}

func Test_OnExitTraceError(t *testing.T) {

	log := tests.LogrusCapture(func() {
		OnExitTraceError(context.Background(), nil, "test")
	})
	require.EqualValues(t, log, "")

	log = tests.LogrusCapture(func() {
		nerr := fmt.Errorf("Any message")
		OnExitTraceError(context.Background(), &nerr, "test")
	})
	require.EqualValues(t, log, "")

	errs := []Error{
		WarningError(errors.New("math: can't divide by zero"), "Any message"),
		TimeoutError(errors.New("math: can't divide by zero"), 30*time.Second, "Any message"),
		AbortedError(errors.New("math: can't divide by zero"), "Any message"),
		OverflowError(errors.New("math: can't divide by zero"), 30, "Any message"),
		ExecutionError(errors.New("exit error"), "Any message"),
		NewError("Any message"),
	}

	for i := range errs {
		log = tests.LogrusCapture(func() {
			err := func(in_err Error) (out_err error) {
				defer OnExitTraceError(context.Background(), &in_err, "test")
				return in_err
			}(errs[i])
			if err == nil {
				t.Fail()
			}

		})
		require.EqualValues(t, log, "")
	}

}

func Test_OnExitWrapError(t *testing.T) {

	log := tests.LogrusCapture(func() {
		OnExitWrapError(context.Background(), nil, "")
	})
	require.EqualValues(t, log, "")

	log = tests.LogrusCapture(func() {
		errv := NewError("Any message")
		OnExitWrapError(context.Background(), &errv, "test")
	})
	if !strings.Contains(log, "OnExitWrapError only works when 'err' is a '*error'") {
		t.Fail()
	}
	log = tests.LogrusCapture(func() {
		errv := WarningError(errors.New("math: can't divide by zero"), "Any message")
		OnExitWrapError(context.Background(), &errv, "test")
	})
	if !strings.Contains(log, "unexpected type '**fail.ErrWarning'") {
		t.Fail()
	}
	log = tests.LogrusCapture(func() {
		errv := errors.New("Any message")
		OnExitWrapError(context.Background(), &errv, "test")
	})
	require.EqualValues(t, log, "")

}

func Test_OnExitConvertToGRPCStatus(t *testing.T) {

	err := grpcstatus.Error(codes.NotFound, "id was not found")
	OnExitConvertToGRPCStatus(context.Background(), &err)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*status.Error")

	errv := errors.New("Any message")
	OnExitConvertToGRPCStatus(context.Background(), &errv)
	require.EqualValues(t, reflect.TypeOf(errv).String(), "*status.Error")

}

func Test_OnPanic(t *testing.T) {

	err := func() (err error) {
		spew.Dump(&err)
		defer OnPanic(&err)
		panic("mayday")
	}()
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrRuntimePanic")

	log := tests.LogrusCapture(func() {
		_ = func() (err *Error) {
			err = nil
			defer OnPanic(err)
			panic("mayday")
		}()
	})
	require.Contains(t, log, "intercepted panic but '*err' is nil")

	log = tests.LogrusCapture(func() {
		_ = func() (err *error) {
			err = nil
			defer OnPanic(err)
			panic("mayday")
		}()
	})
	require.Contains(t, log, "intercepted panic but '*err' is nil")

	log = tests.LogrusCapture(func() {
		_ = func() (err error) {
			defer OnPanic(struct{}{})
			panic("mayday")
		}()
	})
	require.Contains(t, log, "intercepted panic but parameter 'err' is invalid")

	log = tests.LogrusCapture(func() {
		_ = func() (err error) {
			err = errors.New("Any message")
			defer OnPanic(&err)
			panic("mayday")
		}()
	})
	require.Contains(t, log, "fail.OnPanic")

	testlist := []struct {
		name     string
		err      Error
		contains string
	}{
		{name: "ErrorList", err: NewErrorList([]error{errors.New("Any message")})},
		{name: "NotFoundError", err: NotFoundError("Any message")},
		{name: "ErrUnqualified", err: NewError("Any message")},
		{name: "ErrWarning", err: &ErrWarning{errorCore: createErrorCore("Any message")}},
		{name: "ErrTimeout", err: &ErrTimeout{errorCore: createErrorCore("Any message")}},
		{name: "ErrAborted", err: &ErrAborted{errorCore: createErrorCore("Any message")}},
		{name: "ErrRuntimePanic", err: &ErrRuntimePanic{errorCore: createErrorCore("Any message")}},
		{name: "ErrNotAvailable", err: &ErrNotAvailable{errorCore: createErrorCore("Any message")}},
		{name: "ErrDuplicate", err: &ErrDuplicate{errorCore: createErrorCore("Any message")}},
		{name: "ErrInvalidRequest", err: &ErrInvalidRequest{errorCore: createErrorCore("Any message")}},
		{name: "ErrSyntax", err: &ErrSyntax{errorCore: createErrorCore("Any message")}},
		{name: "ErrNotAuthenticated", err: &ErrNotAuthenticated{errorCore: createErrorCore("Any message")}},
		{name: "ErrForbidden", err: &ErrForbidden{errorCore: createErrorCore("Any message")}},
		{name: "ErrOverflow", err: &ErrOverflow{errorCore: createErrorCore("Any message")}},
		{name: "ErrOverload", err: &ErrOverload{errorCore: createErrorCore("Any message")}},
		{name: "ErrNotImplemented", err: &ErrNotImplemented{errorCore: createErrorCore("Any message")}},
		{name: "ErrInvalidInstance", err: &ErrInvalidInstance{errorCore: createErrorCore("Any message")}},
		{name: "ErrInvalidParameter", err: &ErrInvalidParameter{errorCore: createErrorCore("Any message")}},
		{name: "ErrInvalidInstanceContent", err: &ErrInvalidInstanceContent{errorCore: createErrorCore("Any message")}},
		{name: "ErrInconsistent", err: &ErrInconsistent{errorCore: createErrorCore("Any message")}},
		{name: "ErrExecution", err: &ErrExecution{errorCore: createErrorCore("Any message")}},
		{name: "ErrAlteredNothing", err: &ErrAlteredNothing{errorCore: createErrorCore("Any message")}},
		{name: "ErrUnknown", err: &ErrUnknown{errorCore: createErrorCore("Any message")}},
	}

	for i := range testlist {
		t.Run(testlist[i].name, func(t *testing.T) {
			log = tests.LogrusCapture(func() {
				_ = func() (err Error) {
					defer OnPanic(testlist[i].err)
					panic("mayday")
				}()
			})
			require.Contains(t, log, "fail.OnPanic")
		})
	}

}

func Test_SilentOnPanic(t *testing.T) {

	err := func() (err error) {
		spew.Dump(&err)
		defer SilentOnPanic(&err)
		panic("mayday")
	}()
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrRuntimePanic")

	log := tests.LogrusCapture(func() {
		_ = func() (err *Error) {
			err = nil
			defer SilentOnPanic(err)
			panic("mayday")
		}()
	})
	require.Contains(t, log, "intercepted panic but '*err' is nil")

	log = tests.LogrusCapture(func() {
		_ = func() (err *error) {
			err = nil
			defer SilentOnPanic(err)
			panic("mayday")
		}()
	})
	require.Contains(t, log, "intercepted panic but '*err' is nil")

	log = tests.LogrusCapture(func() {
		_ = func() (err error) {
			defer SilentOnPanic(struct{}{})
			panic("mayday")
		}()
	})
	require.Contains(t, log, "intercepted panic but parameter 'err' is invalid")

	log = tests.LogrusCapture(func() {
		_ = func() (err error) {
			err = errors.New("Any message")
			defer SilentOnPanic(&err)
			panic("mayday")
		}()
	})
	require.Contains(t, log, "fail.SilentOnPanic")

	testlist := []struct {
		name     string
		err      Error
		contains string
	}{
		{name: "ErrorList", err: NewErrorList([]error{errors.New("Any message")})},
		{name: "NotFoundError", err: NotFoundError("Any message")},
		{name: "ErrUnqualified", err: NewError("Any message")},
		{name: "ErrWarning", err: &ErrWarning{errorCore: createErrorCore("Any message")}},
		{name: "ErrTimeout", err: &ErrTimeout{errorCore: createErrorCore("Any message")}},
		{name: "ErrAborted", err: &ErrAborted{errorCore: createErrorCore("Any message")}},
		{name: "ErrRuntimePanic", err: &ErrRuntimePanic{errorCore: createErrorCore("Any message")}},
		{name: "ErrNotAvailable", err: &ErrNotAvailable{errorCore: createErrorCore("Any message")}},
		{name: "ErrDuplicate", err: &ErrDuplicate{errorCore: createErrorCore("Any message")}},
		{name: "ErrInvalidRequest", err: &ErrInvalidRequest{errorCore: createErrorCore("Any message")}},
		{name: "ErrSyntax", err: &ErrSyntax{errorCore: createErrorCore("Any message")}},
		{name: "ErrNotAuthenticated", err: &ErrNotAuthenticated{errorCore: createErrorCore("Any message")}},
		{name: "ErrForbidden", err: &ErrForbidden{errorCore: createErrorCore("Any message")}},
		{name: "ErrOverflow", err: &ErrOverflow{errorCore: createErrorCore("Any message")}},
		{name: "ErrOverload", err: &ErrOverload{errorCore: createErrorCore("Any message")}},
		{name: "ErrNotImplemented", err: &ErrNotImplemented{errorCore: createErrorCore("Any message")}},
		{name: "ErrInvalidInstance", err: &ErrInvalidInstance{errorCore: createErrorCore("Any message")}},
		{name: "ErrInvalidParameter", err: &ErrInvalidParameter{errorCore: createErrorCore("Any message")}},
		{name: "ErrInvalidInstanceContent", err: &ErrInvalidInstanceContent{errorCore: createErrorCore("Any message")}},
		{name: "ErrInconsistent", err: &ErrInconsistent{errorCore: createErrorCore("Any message")}},
		{name: "ErrExecution", err: &ErrExecution{errorCore: createErrorCore("Any message")}},
		{name: "ErrAlteredNothing", err: &ErrAlteredNothing{errorCore: createErrorCore("Any message")}},
		{name: "ErrUnknown", err: &ErrUnknown{errorCore: createErrorCore("Any message")}},
	}

	for i := range testlist {
		t.Run(testlist[i].name, func(t *testing.T) {
			log = tests.LogrusCapture(func() {
				_ = func() (err Error) {
					defer SilentOnPanic(testlist[i].err)
					panic("mayday")
				}()
			})
			require.Contains(t, log, "fail.SilentOnPanic")
		})
	}

}

func Test_IgnoreProblems(t *testing.T) {

	err := func() (err Error) {
		defer IgnoreProblems(&err)
		panic("mayday")
	}()
	require.Nil(t, err)

}

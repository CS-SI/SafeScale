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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func logrus_capture(routine func()) string {

	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	logrus.SetOutput(w)

	routine()

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout
	return string(out)

}

func Test_OnExitLogErrorWithLevel(t *testing.T) {

	log := logrus_capture(func() {
		OnExitLogErrorWithLevel(nil, logrus.WarnLevel)
	})
	require.EqualValues(t, log, "")

	log = logrus_capture(func() {
		OnExitLogErrorWithLevel(struct{}{}, logrus.WarnLevel)
	})
	require.Contains(t, log, "fail.OnExitLogErrorWithLevel()")

	log = logrus_capture(func() {
		nerr := errors.New("Any message")
		OnExitLogErrorWithLevel(&nerr, logrus.WarnLevel)
	})
	require.Contains(t, log, "Any message")

	log = logrus_capture(func() {
		nerr := fmt.Errorf("Any message")
		OnExitLogErrorWithLevel(&nerr, 42)
	})
	require.Contains(t, log, "level=error")

	log = logrus_capture(func() {
		nerr := grpcstatus.Error(codes.FailedPrecondition, "GRPC Error: id was not found")
		OnExitLogErrorWithLevel(&nerr, logrus.WarnLevel)

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
		log = logrus_capture(func() {
			err := func(in_err Error) (out_err error) {
				defer OnExitLogErrorWithLevel(&in_err, logrus.WarnLevel)
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

	log := logrus_capture(func() {
		OnExitLogError(nil, "test")
	})
	require.EqualValues(t, log, "")

	log = logrus_capture(func() {
		nerr := fmt.Errorf("Any message")
		OnExitLogError(&nerr, "test")
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
		log = logrus_capture(func() {
			err := func(in_err Error) (out_err error) {
				defer OnExitLogError(&in_err, "test")
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

	log := logrus_capture(func() {
		OnExitTraceError(nil, "test")
	})
	require.EqualValues(t, log, "")

	log = logrus_capture(func() {
		nerr := fmt.Errorf("Any message")
		OnExitTraceError(&nerr, "test")
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
		log = logrus_capture(func() {
			err := func(in_err Error) (out_err error) {
				defer OnExitTraceError(&in_err, "test")
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

	log := logrus_capture(func() {
		OnExitWrapError(nil, "")
	})
	require.EqualValues(t, log, "")

	log = logrus_capture(func() {
		errv := NewError("Any message")
		OnExitWrapError(&errv, "test")
	})
	if !strings.Contains(log, "OnExitWrapError only works when 'err' is a '*error'") {
		t.Fail()
	}
	log = logrus_capture(func() {
		errv := WarningError(errors.New("math: can't divide by zero"), "Any message")
		OnExitWrapError(&errv, "test")
	})
	if !strings.Contains(log, "unexpected type '**fail.ErrWarning'") {
		t.Fail()
	}
	log = logrus_capture(func() {
		errv := errors.New("Any message")
		OnExitWrapError(&errv, "test")
	})
	require.EqualValues(t, log, "")

}

func Test_OnExitConvertToGRPCStatus(t *testing.T) {

	err := grpcstatus.Error(codes.NotFound, "id was not found")
	OnExitConvertToGRPCStatus(&err)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*status.Error")

	errv := errors.New("Any message")
	OnExitConvertToGRPCStatus(&errv)
	require.EqualValues(t, reflect.TypeOf(errv).String(), "*status.Error")

}

func Test_OnPanic(t *testing.T) {

	err := func() (err error) {
		spew.Dump(&err)
		defer OnPanic(&err)
		panic("mayday")
	}()
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrRuntimePanic")

	log := logrus_capture(func() {
		_ = func() (err *Error) {
			err = nil
			defer OnPanic(err)
			panic("mayday")
		}()
	})
	require.Contains(t, log, "intercepted panic but '*err' is nil")

	log = logrus_capture(func() {
		_ = func() (err Error) {
			err = NotFoundError("Any message")
			defer OnPanic(&err)
			panic("mayday")
		}()
	})
	require.Contains(t, log, "fail.OnPanic")

	log = logrus_capture(func() {
		_ = func() (err *error) {
			err = nil
			defer OnPanic(err)
			panic("mayday")
		}()
	})
	require.Contains(t, log, "intercepted panic but '*err' is nil")

	log = logrus_capture(func() {
		_ = func() (err error) {
			err = errors.New("Any message")
			defer OnPanic(&err)
			panic("mayday")
		}()
	})
	require.Contains(t, log, "fail.OnPanic")

	log = logrus_capture(func() {
		_ = func() (err error) {
			defer OnPanic(struct{}{})
			panic("mayday")
		}()
	})
	require.Contains(t, log, "intercepted panic but parameter 'err' is invalid")

}

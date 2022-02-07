/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
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
		nerr := errors.New("Any message")
		OnExitLogErrorWithLevel(&nerr, logrus.WarnLevel)
	})
	if !strings.Contains(log, "Any message") {
		t.Fail()
	}

	log = logrus_capture(func() {
		nerr := fmt.Errorf("Any message")
		OnExitLogErrorWithLevel(&nerr, 42)
	})
	if !strings.Contains(log, "level=error") {
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
				defer OnExitLogErrorWithLevel(&in_err, logrus.WarnLevel)
				return in_err
			}(errs[i])
			if err == nil {
				t.Fail()
			}

		})
		if !strings.Contains(log, "level=warning") {
			t.Fail()
		}
		if !strings.Contains(log, "Any message") {
			t.Fail()
		}
	}

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

	log := logrus_capture(func() {
		errv := errors.New("Any message")
		OnExitConvertToGRPCStatus(&errv)
	})
	require.EqualValues(t, log, "")

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
	require.EqualValues(t, strings.Contains(log, "intercepted panic but '*err' is nil"), true)

	log = logrus_capture(func() {
		_ = func() (err Error) {
			err = NotFoundError("Any message")
			defer OnPanic(&err)
			panic("mayday")
		}()
	})
	require.EqualValues(t, strings.Contains(log, "fail.OnPanic"), true)

	log = logrus_capture(func() {
		_ = func() (err *error) {
			err = nil
			defer OnPanic(err)
			panic("mayday")
		}()
	})
	require.EqualValues(t, strings.Contains(log, "intercepted panic but '*err' is nil"), true)

	log = logrus_capture(func() {
		_ = func() (err error) {
			err = errors.New("Any message")
			defer OnPanic(&err)
			panic("mayday")
		}()
	})
	require.EqualValues(t, strings.Contains(log, "fail.OnPanic"), true)

}

// -------- tests for log helpers ---------
func getNotFoundError() (err error) {
	defer OnExitLogError(&err)
	return NotFoundError("not there !!!")
}

func getNotFoundErrorWithLog() (err error) {
	defer OnExitLogError(&err)
	return NotFoundError("not there !!!")
}

func doPanic() {
	panic("Ouch")
}

func liveDangerously(panicflag bool) (err error) {
	spew.Dump(&err)
	defer OnPanic(&err)

	if panicflag {
		doPanic()
	}

	return nil
}

func TestLogErrorWithPanic(t *testing.T) {
	err := liveDangerously(true)
	if err == nil {
		t.Errorf("Panic error shouldn't go unnoticed")
	} else {
		message := err.Error()
		if !strings.Contains(message, "Ouch") {
			t.Errorf("Panic should contain panic info...")
		}
	}
}

func TestExitLogError(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logrus.SetOutput(w)

	err := getNotFoundErrorWithLog()
	if err == nil {
		t.Fail()
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	tk := string(out)

	if !strings.Contains(tk, "getNotFoundErrorWithLog") {
		t.Fail()
	}
}

func callToSomethingThatReturnsErr() error {
	return getNotFoundErrorWithLog()
}

func callToSomethingThatReturnsErrButLogsIt() (err error) {
	defer OnExitLogErrorWithLevel(&err, logrus.WarnLevel)
	return getNotFoundError()
}

func callToSomethingThatReturnsErrButLogItWithWarning() (err error) {
	defer OnExitLogError(&err)
	return getNotFoundError()
}

func TestOnExit(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logrus.SetOutput(w)

	err := callToSomethingThatReturnsErr()
	if err == nil {
		t.Fail()
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	tk := string(out)

	if !strings.Contains(tk, "getNotFoundErrorWithLog") {
		t.Fail()
	}
}

func TestOnExitAndLog(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logrus.SetOutput(w)

	err := callToSomethingThatReturnsErrButLogsIt()
	if err == nil {
		t.Fail()
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	tk := string(out)

	if !strings.Contains(tk, "callToSomethingThatReturnsErrButLogsIt") {
		t.Fail()
	}
}

func TestOnExitAndLogWithWarning(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logrus.SetOutput(w)

	err := callToSomethingThatReturnsErrButLogItWithWarning()
	if err == nil {
		t.Fail()
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	tk := string(out)

	if !strings.Contains(tk, "callToSomethingThatReturnsErrButLogItWithWarning") {
		t.Fail()
	}
}

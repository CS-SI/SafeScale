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
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"

	"github.com/sirupsen/logrus"
)

// -------- tests for log helpers ---------

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

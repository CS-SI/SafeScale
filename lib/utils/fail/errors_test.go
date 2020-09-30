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
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sirupsen/logrus"
)

func lazyDevs() error {
	return NotImplementedError("no time for this")
}

func TestNotImplementedError(t *testing.T) {
	what := lazyDevs()
	if what == nil {
		t.Fatalf("unexpected nil error")
	}
	whatContent := what.Error()
	if !strings.Contains(whatContent, "fail.lazyDevs") {
		t.Errorf("Expected 'utils.lazyDevs' in error content but found: %s", whatContent)
	}
}

// -------- tests for log helpers ---------

func chaos() (err error) {
	logrus.SetOutput(os.Stdout)
	defer OnExitLogErrorWithLevel("Here it begins", &err, logrus.InfoLevel)()

	// return nil
	return fmt.Errorf("it failed")
}

func success() (err error) {
	logrus.SetOutput(os.Stdout)
	defer OnExitLogErrorWithLevel("Here it begins", &err, logrus.InfoLevel)()

	return nil
}

func TestLogErrorWithLevelChaos(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := chaos()
	if err == nil {
		t.Fail()
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	if !strings.Contains(string(out), errorOccurred) {
		t.Fail()
	}
}

func TestLogErrorWithLevelOrder(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := success()
	if err != nil {
		t.Fail()
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	if strings.Contains(string(out), errorOccurred) {
		t.Fail()
	}
}

func doPanic() {
	panic("Ouch")
}

func liveDangerously(panicflag bool) (err error) {
	defer OnPanic(&err)()

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

func sender() error {
	return Errorf("what", Errorf("something else", nil))
}

func specialSender() error {
	return InvalidInstanceError()
}

func TestRecognizeErrCore(t *testing.T) {
	var err error
	err = sender()

	if !ImplementsCauser(err) {
		t.Fail()
	}

	if eb, ok := err.(causer); ok {
		require.True(t, strings.Contains(eb.Error(), "caused by"))
		require.False(t, strings.Contains(eb.Message(), "caused by"))
	} else {
		t.Fail()
	}
}

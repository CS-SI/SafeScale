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

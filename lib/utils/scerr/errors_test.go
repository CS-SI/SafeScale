package scerr

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func lazyDevs() error {
	return NotImplementedError("no time for this")
}

func TestNotImplementedError(t *testing.T) {
	what := lazyDevs()
	assert.NotNil(t, what)
	whatContent := what.Error()
	if !strings.Contains(whatContent, "scerr.lazyDevs") {
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

func lazyDevsWithCaveat() error {
	return NotImplementedErrorWithReason("LazyDevsWithCaveat() not implemented yet!", "API not ready").WithField("provider", "Juawei")
}

func lazyDevsPlainAndSimple() error {
	return NotImplementedError("").WithField("provider", "Juawei")
}

func moreLazyErrors() error {
	return NotFoundError("We lost something !!").WithField("node", "master-x").WithField("provider", "OWH")
}

func getNotFoundErrorWithFields() error {
	return NotFoundError("We lost something !!").WithField("node", "master-x").WithField("provider", "OWH")
}

func getNotFoundErrorWithFieldsAndConsequences() error {
	nfe := NotFoundError("We lost something !!").WithField("node", "master-x").WithField("provider", "OWH")
	return AddConsequence(nfe, fmt.Errorf("something else ... "))
}

func TestEnrichedError(t *testing.T) {
	x := moreLazyErrors()
	x = WithField(x, "region", "europe1")
	x = AddConsequence(x, fmt.Errorf("connection lost"))
	assert.NotNil(t, x)

	errct := x.Error()
	assert.NotNil(t, errct)
	if !strings.Contains(errct, "europe1") {
		t.Errorf("Information loss : %s", errct)
	}

	if !strings.Contains(errct, "connection") {
		t.Errorf("Information loss : %s", errct)
	}
}

func TestWithFields(t *testing.T) {
	x := lazyDevsWithCaveat()
	assert.NotNil(t, x)

	errct := x.Error()
	if !strings.Contains(errct, "Lazy") {
		t.Errorf("We lost the what ! : %s", errct)
	}
	if !strings.Contains(errct, "API not ready") {
		t.Errorf("We lost the why ! : %s", errct)
	}

	x = lazyDevsPlainAndSimple()
	assert.NotNil(t, x)

	errct = x.Error()
	if !strings.Contains(errct, "lazyDevsPlainAndSimple") {
		t.Errorf("We lost the function name ! : %s", errct)
	}
}

func TestWithFieldsAgain(t *testing.T) {
	x := moreLazyErrors()
	assert.NotNil(t, x)

	errct := x.Error()
	if !strings.Contains(errct, "master-x") {
		t.Errorf("We lost a key ! : %s", errct)
	}
	if !strings.Contains(errct, "OWH") {
		t.Errorf("We lost a value ! : %s", errct)
	}
}

func TestIsError(t *testing.T) {
	x := moreLazyErrors()
	assert.NotNil(t, x)

	iserr := IsError(x)
	if !iserr {
		t.Errorf("This should be an error! : %s", x)
	}
}

func getNotFoundError() error {
	return NotFoundError("not there !!!")
}

func TestKeepErrorType(t *testing.T) {
	mzb := getNotFoundError()
	if cae, ok := mzb.(*ErrNotFound); !ok {
		t.Errorf("Error type was lost in translation !!: %T", cae)
	}

	mzb = getNotFoundErrorWithFields()
	if cae, ok := mzb.(*ErrNotFound); !ok {
		t.Errorf("Error type was lost in translation !!: %T", cae)
	}

	mzb = getNotFoundErrorWithFieldsAndConsequences()
	if cae, ok := mzb.(*ErrNotFound); !ok {
		t.Errorf("Error type was lost in translation !!: %T", cae)
	}
}

func getNotFoundErrorWithLog() (err error) {
	defer OnExitLogError("", &err)()
	return NotFoundError("not there !!!")
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
	defer OnExitLogErrorWithLevel("", &err, logrus.WarnLevel)()
	err = getNotFoundError()
	return err
}

func callToSomethingThatReturnsErrButLogItWithWarning() (err error) {
	defer OnExitLogError("", &err)()
	err = getNotFoundError()
	return err
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

func TestUncathegorizedError(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logrus.SetOutput(w)

	err := func() error {
		return InconsistentError("")
	}()
	if err == nil {
		t.Fail()
	}

	if err != nil {
		logrus.Warn(err.Error())
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	tk := string(out)

	if !strings.Contains(tk, "uncategorized error occurred:") {
		t.Fail()
	}
}

func TestNotUncathegorizedError(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logrus.SetOutput(w)

	err := func() error {
		return InconsistentError("something")
	}()
	if err == nil {
		t.Fail()
	}

	if err != nil {
		logrus.Warn(err.Error())
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	tk := string(out)

	if strings.Contains(tk, "uncategorized error occurred:") {
		t.Fail()
	}
	if !strings.Contains(tk, "something") {
		t.Fail()
	}
}

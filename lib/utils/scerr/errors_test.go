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

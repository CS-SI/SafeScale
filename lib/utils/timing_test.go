package utils

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func chaos() (err error) {
	logrus.SetOutput(os.Stdout)
	defer TimerErrWithLevel("Here it begins", &err, logrus.InfoLevel)()

	// return nil
	return fmt.Errorf("It failed")
}

func success() (err error) {
	logrus.SetOutput(os.Stdout)
	defer TimerErrWithLevel("Here it begins", &err, logrus.InfoLevel)()

	return nil
}

func TestTimerErrWithLevelChaos(t *testing.T) {
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

	if !strings.Contains(string(out), "WITH ERROR") {
		t.Fail()
	}
}

func TestTimerErrWithLevelOrder(t *testing.T) {
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

	if strings.Contains(string(out), "WITH ERROR") {
		t.Fail()
	}
}
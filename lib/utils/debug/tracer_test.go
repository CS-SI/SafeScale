package debug

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sirupsen/logrus"
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

func trackSomething(ref string) (err error) {
	tracer := NewTracer(nil, true, "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())
	defer fail.OnExitWrapError(&err, "something bad happened")
	defer fail.OnPanic(&err)

	tracer.TraceAsError("you fade away")

	return fmt.Errorf("terrible glimpses flicker in my mind")
}

func rage() string {
	return logrus_capture(func() {
		_ = trackSomething("you have reason to fear")
	})
}

func Test_tracer_EnteringMessage(t *testing.T) {
	ct := rage()
	failed := false
	if !strings.Contains(ct, "something bad happened: terrible glimpses") {
		failed = true
	}
	if !strings.Contains(ct, "tracer_test.go:37]: you fade away") {
		failed = true
	}
	if !strings.Contains(ct, "tracer_test.go:39]: something bad") {
		failed = true
	}
	if failed {
		t.Error(ct)
	} else {
		t.Log(ct)
	}
}

package debug

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/tests"
)

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
	return tests.LogrusCapture(func() {
		_ = trackSomething("you have reason to fear")
	})
}

func Test_tracer_EnteringMessage(t *testing.T) {
	ct := rage()
	failed := false
	if !strings.Contains(ct, "something bad happened: terrible glimpses") {
		failed = true
	}
	if !strings.Contains(ct, "you fade away") {
		failed = true
	}
	if failed {
		t.Error(ct)
	} else {
		t.Log(ct)
	}
}

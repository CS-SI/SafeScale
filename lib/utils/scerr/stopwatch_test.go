package scerr

import (
	"strings"
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	stowa := Stopwatch{}

	res := FormatDuration(stowa.Duration())
	if !strings.Contains(res, "1 ms") {
		t.Errorf("This should be 1 ms and it isn't")
	}
}

func TestStopDuration(t *testing.T) {
	stowa := Stopwatch{}

	stowa.Stop()
	stowa.Stop()

	res := FormatDuration(stowa.Duration())
	if !strings.Contains(res, "1 ms") {
		t.Errorf("This should be 1 ms and it isn't")
	}
}

func TestStartStopDuration(t *testing.T) {
	stowa := Stopwatch{}

	stowa.Start()
	time.Sleep(10 * time.Millisecond)
	stowa.Stop()

	res := FormatDuration(stowa.Duration())
	if !strings.Contains(res, "10 ms") {
		t.Errorf("This should be 10 ms and it isn't: %s", res)
	}
}

func TestStartStopDurationAgain(t *testing.T) {
	stowa := Stopwatch{}

	stowa.Start()
	time.Sleep(10 * time.Millisecond)
	stowa.Stop()
	time.Sleep(time.Second)
	stowa.Start()
	time.Sleep(20 * time.Millisecond)
	stowa.Start()
	stowa.Stop()

	res := FormatDuration(stowa.Duration())
	if !strings.Contains(res, "30 ms") {
		t.Errorf("This should be 30 ms and it isn't: %s", res)
	}
}

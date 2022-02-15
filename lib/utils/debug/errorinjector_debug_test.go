//go:build debug
// +build debug

package debug

import (
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

func supernatural() fail.Error {
	return nil
}

func TestInjectPlannedFailWithProbability(t *testing.T) {
	err := setup("errorinjector_debug_test.go:23:p:1") // line 23 (the one with InjectPlannedFail, with probability 1 -> 100%)
	if err != nil {
		return
	}

	xerr := supernatural()
	xerr = InjectPlannedFail(xerr)
	if xerr == nil {
		t.FailNow()
	}
}

func TestInjectPlannedFailWithIteration(t *testing.T) {
	err := setup("errorinjector_debug_test.go:38:i:4") // line 38 (the one with InjectPlannedFail, iteration, after the 4th time, it always breaks)
	if err != nil {
		return
	}

	failures := 0
	for i := 0; i < 10; i++ {
		xerr := supernatural()
		xerr = InjectPlannedFail(xerr)
		if xerr == nil {
			failures += 1
			if i >= 3 { // 4h time until 10 -> 4..10
				t.Fail()
			}
		}
	}

	if failures != 3 {
		t.FailNow()
	}
}

func TestInjectPlannedFailOnceWithIteration(t *testing.T) {
	err := setup("errorinjector_debug_test.go:60:o:4") // line 60 (the one with InjectPlannedFail, iterating ONLY the 4th time breaks)
	if err != nil {
		return
	}

	for i := 0; i < 10; i++ {
		xerr := supernatural()
		xerr = InjectPlannedFail(xerr)
		if xerr != nil {
			if i != 3 { // 4th time -> 0..3
				t.Fail()
			}
		}
	}
}

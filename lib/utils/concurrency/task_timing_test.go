//go:build alltests
// +build alltests

package concurrency

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

func TestChildrenWaitingGameWithContextCancelfuncsWF(t *testing.T) {
	funk := func(ind int, sleep uint, lat uint, trigger uint, errorExpected bool) {
		fmt.Printf("--- funk #%d ---\n", ind)

		ctx, cafu := context.WithCancel(context.TODO())
		single, xerr := NewTaskWithContext(ctx)
		require.NotNil(t, single)
		require.Nil(t, xerr)

		xerr = single.SetID(fmt.Sprintf("single-%d", ind))
		require.Nil(t, xerr)

		begin := time.Now()
		single, xerr = single.Start(taskgen(int(sleep), int(sleep), int(lat), 0, 0, 0, false), nil)
		require.Nil(t, xerr)

		go func() {
			time.Sleep(time.Duration(trigger) * time.Millisecond)
			cafu()
		}()

		_, _, xerr = single.WaitFor(5 * time.Second)
		totalEnd := time.Since(begin)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrAborted:
			default:
				t.Errorf("Unexpected error occurred in %s (%s)", xerr.Error(), reflect.TypeOf(xerr).String())
			}
		}

		if !((xerr != nil) == errorExpected) {
			if xerr != nil {
				if !strings.Contains(xerr.Error(), "inconsistent") {
					t.Errorf(
						"Failure in test %d: %v, %v, %t: wrong error: %v!", ind, sleep, trigger, errorExpected, xerr,
					)
				}
			} else {
				t.Errorf("Failure in test %d: %v, %v, %t: wrong error!", ind, sleep, trigger, errorExpected)
			}
		}

		tolerance := func(in float64, percent uint) float32 {
			return float32(in * (100.0 + float64(percent)) / 100.0)
		}

		// is the 20% vs latency ratio important ?
		toleratedDuration := time.Duration(tolerance(math.Min(float64(trigger), float64(sleep)), 20)) * time.Millisecond
		if totalEnd > toleratedDuration {
			t.Logf("Warning in test %d: %v, %v, %t: We waited too much! %v > %v", ind, sleep, trigger, errorExpected, totalEnd, toleratedDuration)
		}
	}

	for i := 0; i < 5; i++ {
		// tests are right, errorExpected it what it should be
		// previous versions got the work done fast enough, now we don't, why ?
		// if trigger >= (sleep + latency) and we have an error (we should NOT), this is failure
		funk(1, 10, 5, 1, true)
		funk(2, 10, 5, 5, true) // latency matters ?
		funk(3, 10, 5, 6, true) // this test and the previous should be equivalent
		// VPL: Task took 12.22ms to end, cancel hits at 12.16ms -> Aborted
		funk(4, 10, 5, 20, false) // latency matters ?
		funk(5, 10, 5, 21, false)
		funk(6, 50, 10, 80, false)
		funk(7, 50, 10, 300, false)
		funk(8, 50, 10, 3000, false)
		funk(9, 50, 10, 6000, false)
		funk(10, 50, 10, 45, true) // latency matters, this sometimes fails
		funk(11, 50, 10, 46, true) // latency matters, this sometimes fails
		// VPL: on macM1, cancel signal hits at 51.80ms, task detects abort at 57.11ms -> Aborted
		funk(12, 60, 20, 63, false) // latency matters, this sometimes fails
		// VPL: on macM1, cancel signals hits at 52.13ms, task detects abort at 57.36ms -> Aborted
		funk(13, 60, 20, 64, false) // latency matters, this sometimes fails
		funk(14, 60, 20, 70, false) // latency matters, this sometimes fails
		// VPL: on macM1, task ended its work after 62.71ms, before cancel hits -> no error
		funk(15, 60, 20, 73, false) // if we go far enough, no errors
		funk(16, 60, 20, 83, false) // if we go far enough, no errors
	}
}

func TestChildrenWaitingGameEnoughTimeTooManyFailures(t *testing.T) {
	funk := func(index int, rounds int, lower int, upper int, latency int, margin int, gcpressure int) {
		failures := 0
		for iter := 0; iter < rounds; iter++ {
			overlord, xerr := NewTaskGroupWithParent(nil)
			require.NotNil(t, overlord)
			require.Nil(t, xerr)
			xerr = overlord.SetID("/parent")
			require.Nil(t, xerr)

			theID, xerr := overlord.GetID()
			require.Nil(t, xerr)
			require.NotEmpty(t, theID)

			begin := time.Now()
			for ind := 0; ind < gcpressure; ind++ {
				_, xerr := overlord.Start(taskgen(lower, upper, latency, 0, 0, 0, false), nil, InheritParentIDOption, AmendID(fmt.Sprintf("/child-%d", ind)))
				if xerr != nil {
					t.Errorf("Test %d: Unexpected: %s", index, xerr)
					t.FailNow()
					return
				}
			}
			childrenStartDuration := time.Since(begin)
			upbound := int(math.Ceil(float64(upper)/float64(latency)) * float64(latency))
			timeout := time.Duration(upbound+margin) * time.Millisecond
			// Waits that all children have started to access max safely
			begin = time.Now()
			fastEnough, res, xerr := overlord.WaitFor(timeout)
			waitForRealDuration := time.Since(begin)
			if !fastEnough {
				t.Logf("WaitFor failed: %s", xerr)
				if childrenStartDuration > 5*time.Millisecond { // however, it grows with gcpressure
					t.Logf("Launching children took %v", childrenStartDuration)
				}
				t.Logf("WaitFor really waited %v/%v", waitForRealDuration, timeout)
				t.Logf("Test %d, It should be enough time but it wasn't at iteration #%d", index, iter)
				failures++
				if failures > (75 * rounds / 100) {
					t.Errorf("Test %d: too many failures", index)
					t.FailNow()
					return
				}
			} else {
				require.Nil(t, xerr)
				require.NotEmpty(t, res)
			}
		}
	}

	// Look at the pressure supported by GC
	funk(1, 10, 100, 125, 25, 25, 10)
	funk(2, 10, 100, 125, 25, 25, 10)
	funk(3, 10, 100, 125, 25, 25, 10)
	funk(4, 10, 100, 125, 25, 25, 10)
}

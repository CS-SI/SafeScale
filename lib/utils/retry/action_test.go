/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package retry

import (
	"context"
	"errors"
	"fmt"
	mrand "math/rand"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/v22/lib/utils/tests"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func Test_NewAction(t *testing.T) {

	var (
		officer = BackoffSelector()(100 * time.Millisecond)
		arbiter = PrevailDone(Unsuccessful(), Timeout(5*time.Second))
		run     = func() (nested error) {
			return nil
		}
		notify  Notify
		timeout = 5 * time.Second
	)

	action := NewAction(officer, arbiter, run, notify, timeout)
	require.EqualValues(t, "*retry.action", reflect.TypeOf(action).String())

}

func Test_Action(t *testing.T) {

	var (
		run = func() (nested error) {
			return nil
		}
		arbiter = PrevailDone(Unsuccessful(), Timeout(5*time.Second))
		officer = BackoffSelector()(100 * time.Millisecond)
		first   = func() (nested error) {
			return nil
		}
		last = func() (nested error) {
			return nil
		}
		notify Notify
	)

	err := Action(nil, arbiter, officer, first, last, notify)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	//	require.Contains(t, err.Error(), "invalid parameter run"), true)
	require.Contains(t, err.Error(), "cannot be nil!")

	err = Action(run, nil, officer, first, last, notify)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	//	require.Contains(t, err.Error(), "invalid parameter arbiter"), true)
	require.Contains(t, err.Error(), "cannot be nil!")

	err = Action(run, arbiter, nil, first, last, notify)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	//	require.Contains(t, err.Error(), "invalid parameter officer"), true)
	require.Contains(t, err.Error(), "cannot be nil!")

	err = Action(run, arbiter, officer, first, last, notify)
	require.Nil(t, err)

}

func Test_TimeoutSelector(t *testing.T) {

	f := TimeoutSelector(false)
	require.EqualValues(t, "func(retry.action) fail.Error", reflect.TypeOf(f).String())

	f = TimeoutSelector(true)
	require.EqualValues(t, "func(retry.action) fail.Error", reflect.TypeOf(f).String())

}

func Test_DefaultTimeoutSelector(t *testing.T) {

	f := DefaultTimeoutSelector()
	require.EqualValues(t, reflect.TypeOf(f).String(), "func(retry.action) fail.Error")

	os.Setenv("SAFESCALE_TIMEOUT_STYLE", "Hard")
	f = DefaultTimeoutSelector()
	require.EqualValues(t, reflect.TypeOf(f).String(), "func(retry.action) fail.Error")

	os.Setenv("SAFESCALE_TIMEOUT_STYLE", "Soft")
	f = DefaultTimeoutSelector()
	require.EqualValues(t, reflect.TypeOf(f).String(), "func(retry.action) fail.Error")

	os.Setenv("SAFESCALE_TIMEOUT_STYLE", "")
	f = DefaultTimeoutSelector()
	require.EqualValues(t, reflect.TypeOf(f).String(), "func(retry.action) fail.Error")

	os.Setenv("SAFESCALE_TIMEOUT_STYLE", "Banana!")
	f = DefaultTimeoutSelector()
	require.EqualValues(t, reflect.TypeOf(f).String(), "func(retry.action) fail.Error")

}

func Test_BackoffSelector(t *testing.T) {

	backoff := BackoffSelector()
	require.EqualValues(t, reflect.TypeOf(backoff).String(), "retry.Backoff")

	os.Setenv("SAFESCALE_ALGO_DELAY", "Constant")
	backoff = BackoffSelector()
	require.EqualValues(t, reflect.TypeOf(backoff).String(), "retry.Backoff")

	os.Setenv("SAFESCALE_ALGO_DELAY", "Incremental")
	backoff = BackoffSelector()
	require.EqualValues(t, reflect.TypeOf(backoff).String(), "retry.Backoff")

	os.Setenv("SAFESCALE_ALGO_DELAY", "Linear")
	backoff = BackoffSelector()
	require.EqualValues(t, reflect.TypeOf(backoff).String(), "retry.Backoff")

	os.Setenv("SAFESCALE_ALGO_DELAY", "Exponential")
	backoff = BackoffSelector()
	require.EqualValues(t, reflect.TypeOf(backoff).String(), "retry.Backoff")

	os.Setenv("SAFESCALE_ALGO_DELAY", "Fibonacci")
	backoff = BackoffSelector()
	require.EqualValues(t, reflect.TypeOf(backoff).String(), "retry.Backoff")

	os.Setenv("SAFESCALE_ALGO_DELAY", "")
	backoff = BackoffSelector()
	require.EqualValues(t, reflect.TypeOf(backoff).String(), "retry.Backoff")

	os.Setenv("SAFESCALE_ALGO_DELAY", "Banana!")
	backoff = BackoffSelector()
	require.EqualValues(t, reflect.TypeOf(backoff).String(), "retry.Backoff")

}

func Test_WhileUnsuccessful(t *testing.T) {

	// no waitfor
	maxtries := 5
	tries := 0
	err := WhileUnsuccessful(func() error {
		tries++
		if tries >= maxtries {
			return nil
		} else {
			return errors.New("Any errior")
		}
	}, 50*time.Millisecond, -1)
	require.Nil(t, err)
	require.EqualValues(t, tries, maxtries)

	maxtries = 5
	tries = 0
	err = WhileUnsuccessful(func() error {
		tries++
		if tries >= maxtries {
			return nil
		} else {
			return errors.New("Any errior")
		}
	}, 50*time.Millisecond, -1)
	require.Nil(t, err)
	require.EqualValues(t, tries, maxtries)

}

func Test_WhileUnsuccessfulWithLimitedRetries(t *testing.T) {

	log := tests.LogrusCapture(func() {
		err := WhileUnsuccessfulWithLimitedRetries(
			func() error {
				return nil
			},
			50*time.Millisecond,
			40*time.Millisecond,
			3,
		)
		require.Nil(t, err)
	})
	require.Contains(t, log, "'delay' greater than 'timeout'")

	err := WhileUnsuccessfulWithLimitedRetries(
		func() error {
			return nil
		},
		-1*time.Millisecond,
		40*time.Millisecond,
		3,
	)
	require.Nil(t, err)

	err = WhileUnsuccessfulWithLimitedRetries(
		func() error {
			return nil
		},
		50*time.Millisecond,
		-1*time.Millisecond,
		3,
	)
	require.Nil(t, err)

	err = WhileUnsuccessfulWithLimitedRetries(
		func() error {
			return nil
		},
		50*time.Millisecond,
		-1*time.Millisecond,
		0,
	)
	require.Nil(t, err)

	err = WhileUnsuccessfulWithLimitedRetries(
		func() error {
			return nil
		},
		50*time.Millisecond,
		1*time.Second,
		3,
	)
	require.Nil(t, err)

	err = WhileUnsuccessfulWithLimitedRetries(
		func() error {
			return nil
		},
		50*time.Millisecond,
		1*time.Second,
		0,
	)
	require.Nil(t, err)

}

func Test_WhileUnsuccessfulWithHardTimeoutWithNotifier(t *testing.T) {

	log := tests.LogrusCapture(func() {
		err := WhileUnsuccessfulWithHardTimeoutWithNotifier(
			func() error {
				return nil
			},
			100*time.Millisecond,
			40*time.Millisecond,
			DefaultNotifier(),
		)
		require.Nil(t, err)
	})

	require.Contains(t, log, "'delay' greater than 'timeout'")

	err := WhileUnsuccessfulWithHardTimeoutWithNotifier(
		func() error {
			return nil
		},
		-1*time.Millisecond,
		40*time.Millisecond,
		DefaultNotifier(),
	)
	require.Nil(t, err)

	/*
		err = WhileUnsuccessfulWithHardTimeoutWithNotifier(
			func() error {
				return nil
			},
			100*time.Millisecond,
			-1*time.Millisecond,
			DefaultNotifier(),
		)
		require.Nil(t, err)
	*/

	err = WhileUnsuccessfulWithHardTimeoutWithNotifier(
		func() error {
			return nil
		},
		100*time.Millisecond,
		1*time.Second,
		DefaultNotifier(),
	)
	require.Nil(t, err)

}

func Test_WhileUnsuccessfulWithNotify(t *testing.T) {

	log := tests.LogrusCapture(func() {
		err := WhileUnsuccessfulWithNotify(
			func() error {
				return nil
			},
			50*time.Millisecond,
			40*time.Millisecond,
			DefaultNotifier(),
		)
		require.Nil(t, err)
	})

	require.Contains(t, log, "'delay' greater than 'timeout'")

	err := WhileUnsuccessfulWithNotify(
		func() error {
			return nil
		},
		-1*time.Millisecond,
		40*time.Millisecond,
		nil,
	)
	require.Contains(t, err.Error(), "cannot be nil")

	err = WhileUnsuccessfulWithNotify(
		func() error {
			return nil
		},
		-1*time.Millisecond,
		40*time.Millisecond,
		DefaultNotifier(),
	)
	require.Nil(t, err)

	err = WhileUnsuccessfulWithNotify(
		func() error {
			return nil
		},
		50*time.Millisecond,
		-1*time.Millisecond,
		DefaultNotifier(),
	)
	require.Nil(t, err)

	err = WhileUnsuccessfulWithNotify(
		func() error {
			return nil
		},
		50*time.Millisecond,
		1*time.Second,
		DefaultNotifier(),
	)
	require.Nil(t, err)

}

func Test_WhileUnsuccessfulWithAggregator(t *testing.T) {

	arb := func(arbiters ...Arbiter) Arbiter {
		var arb Arbiter
		if len(arbiters) > 0 {
			arb = arbiters[0]
		}
		return arb
	}

	log := tests.LogrusCapture(func() {
		err := WhileUnsuccessfulWithAggregator(
			func() error {
				return nil
			},
			50*time.Millisecond,
			40*time.Millisecond,
			arb,
			DefaultNotifier(),
		)
		require.Nil(t, err)
	})

	require.Contains(t, log, "'delay' greater than 'timeout'")

	err := WhileUnsuccessfulWithAggregator(
		func() error {
			return nil
		},
		-1*time.Millisecond,
		40*time.Millisecond,
		arb,
		nil,
	)
	require.Contains(t, err.Error(), "cannot be nil")

	err = WhileUnsuccessfulWithAggregator(
		func() error {
			return nil
		},
		-1*time.Millisecond,
		40*time.Millisecond,
		arb,
		DefaultNotifier(),
	)
	require.Nil(t, err)

	err = WhileUnsuccessfulWithAggregator(
		func() error {
			return nil
		},
		50*time.Millisecond,
		-1*time.Millisecond,
		arb,
		DefaultNotifier(),
	)
	require.Nil(t, err)

	err = WhileUnsuccessfulWithAggregator(
		func() error {
			return nil
		},
		50*time.Millisecond,
		1*time.Second,
		arb,
		DefaultNotifier(),
	)
	require.Nil(t, err)

}

func Test_WhileSuccessful(t *testing.T) {

	// no waitfor
	maxtries := 5
	tries := 0
	err := WhileUnsuccessful(func() error {
		tries++
		if tries >= maxtries {
			return nil
		} else {
			return errors.New("Any errior")
		}
	}, 50*time.Millisecond, -1)
	require.Nil(t, err)
	require.EqualValues(t, tries, maxtries)

	maxtries = 5
	tries = 0
	err = WhileUnsuccessful(func() error {
		tries++
		if tries >= maxtries {
			return nil
		} else {
			return errors.New("Any errior")
		}
	}, 50*time.Millisecond, -1)
	require.Nil(t, err)
	require.EqualValues(t, tries, maxtries)

}

func Test_DefaultNotifier(t *testing.T) {

	forensics := os.Getenv("SAFESCALE_FORENSICS")
	os.Setenv("SAFESCALE_FORENSICS", "test")
	d := DefaultNotifier()
	n := Try{Err: errors.New("nope"), Count: 0}
	log := tests.LogrusCapture(func() {
		d(n, verdict.Retry)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")
	log = tests.LogrusCapture(func() {
		d(n, verdict.Done)
	})
	n = Try{Count: 2}
	require.EqualValues(t, strings.TrimSpace(log), "")
	log = tests.LogrusCapture(func() {
		d(n, verdict.Done)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")
	log = tests.LogrusCapture(func() {
		d(n, verdict.Undecided)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")
	log = tests.LogrusCapture(func() {
		d(n, verdict.Abort)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")
	os.Setenv("SAFESCALE_FORENSICS", forensics)

}

func Test_DefaultMetadataNotifier(t *testing.T) {

	d := DefaultMetadataNotifier("metaID")
	n := Try{Err: errors.New("nope"), Count: 0}
	log := tests.LogrusCapture(func() {
		d(n, verdict.Retry)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")
	log = tests.LogrusCapture(func() {
		d(n, verdict.Done)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")
	log = tests.LogrusCapture(func() {
		d(n, verdict.Done)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")
	log = tests.LogrusCapture(func() {
		d(n, verdict.Undecided)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")
	log = tests.LogrusCapture(func() {
		d(n, verdict.Abort)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")

}

func Test_DefaultNotifierWithContext(t *testing.T) {

	ctx := context.Background()
	d, err := DefaultNotifierWithContext(ctx)
	require.Nil(t, err)

	n := Try{}
	log := tests.LogrusCapture(func() {
		d(n, verdict.Retry)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")

	forensics := os.Getenv("SAFESCALE_FORENSICS")
	os.Setenv("SAFESCALE_FORENSICS", "test")

	n = Try{Err: errors.New("nope"), Count: 0}
	log = tests.LogrusCapture(func() {
		d(n, verdict.Retry)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")
	log = tests.LogrusCapture(func() {
		d(n, verdict.Done)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")
	log = tests.LogrusCapture(func() {
		d(n, verdict.Done)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")
	log = tests.LogrusCapture(func() {
		d(n, verdict.Undecided)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")
	log = tests.LogrusCapture(func() {
		d(n, verdict.Abort)
	})
	require.EqualValues(t, strings.TrimSpace(log), "")

	os.Setenv("SAFESCALE_FORENSICS", forensics)

}

// --------------------------------------------------------------------------------------------------------

func quickSleepy() error {
	fmt.Println("Quick OK")
	time.Sleep(1 * 10 * time.Millisecond)
	return nil
}

func sleepy() error {
	fmt.Println("Slow OK")
	time.Sleep(1 * 60 * 10 * time.Millisecond)
	return nil
}

func sleepyFailure() error {
	fmt.Println("Slow fail")
	time.Sleep(1 * 60 * 10 * time.Millisecond)
	return fmt.Errorf("always fails")
}

func quickSleepyFailure() error {
	fmt.Println("Quick fail")
	time.Sleep(1 * 10 * time.Millisecond)
	return fmt.Errorf("always fails")
}

func complexSleepyFailure() error {
	fmt.Println("Quick fail")
	time.Sleep(1 * 10 * time.Millisecond)
	return fail.NotFoundError("Not here")
}

func CreateErrorWithNConsequences(n uint) (ferr fail.Error) {
	xerr := WhileUnsuccessful(quickSleepyFailure, time.Second, time.Duration(5)*10*time.Millisecond)
	if xerr != nil {
		for loop := uint(0); loop < n; loop++ {
			nerr := fmt.Errorf("random cleanup problem")
			_ = xerr.AddConsequence(nerr)
		}
	}
	return xerr
}

func CreateSkippableError() (ferr fail.Error) {
	xerr := WhileSuccessful(
		func() error {
			fmt.Println("Around the world...")
			return StopRetryError(fail.NotFoundError("wrong place"), "no more")
		}, 1*time.Second, 60*time.Millisecond,
	)
	return xerr
}

func CreateSkippableErrorBis() (ferr fail.Error) {
	xerr := WhileSuccessful(
		func() error {
			fmt.Println("Around the world...")
			return StopRetryError(fail.AbortedError(fail.NotFoundError("wrong place"), "indeed"), "no more")
		}, 1*time.Second, 60*time.Millisecond,
	)
	return xerr
}

func CreateComplexErrorWithNConsequences(n uint) (ferr fail.Error) {
	xerr := WhileUnsuccessful(complexSleepyFailure, time.Second, time.Duration(5)*10*time.Millisecond)
	if xerr != nil {
		for loop := uint(0); loop < n; loop++ {
			nerr := fmt.Errorf("random cleanup problem")
			_ = xerr.AddConsequence(nerr)
		}
	}
	return xerr
}

func JustThrowBasicError() error {
	return fmt.Errorf("something happened")
}

func JustThrowError() fail.Error {
	return abstract.ResourceDuplicateError("host", "boo")
}

func JustThrowComplexError() (ferr fail.Error) {
	xerr := abstract.ResourceDuplicateError("host", "booboo")
	_ = xerr.AddConsequence(fmt.Errorf("cleanup error"))
	return xerr
}

func CreateDeferredErrorWithNConsequences(n uint) (ferr fail.Error) {
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			for loop := uint(0); loop < n; loop++ {
				nerr := fmt.Errorf("random cleanup problem")
				_ = ferr.AddConsequence(nerr)
			}
		}
	}()

	xerr := WhileUnsuccessful(quickSleepyFailure, time.Second, time.Duration(5)*10*time.Millisecond)
	return xerr
}

func CreateWrappedDeferredErrorWithNConsequences(n uint) (ferr fail.Error) {
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			for loop := uint(0); loop < n; loop++ {
				nerr := fmt.Errorf("random cleanup problem")
				_ = ferr.AddConsequence(nerr)
			}
		}
	}()

	xerr := WhileUnsuccessful(quickSleepyFailure, time.Second, time.Duration(5)*10*time.Millisecond)
	return xerr
}

func TestDeferredWrappedConsequence(t *testing.T) {
	recovered := CreateWrappedDeferredErrorWithNConsequences(1)
	if recovered != nil {
		cons := fail.Consequences(recovered)
		if len(cons) == 0 {
			t.Errorf("This error should have consequences...")
		} else {
			for _, con := range cons {
				fmt.Println(con)
			}
		}
	}
}

func TestVerifyErrorType(t *testing.T) {
	recovered := CreateErrorWithNConsequences(1)
	if recovered != nil {
		if _, ok := recovered.(*ErrTimeout); !ok {
			t.Errorf("It should be a 'ErrTimeout', it's instead a '%s'", reflect.TypeOf(recovered).String())
		}

		if cause := fail.Cause(recovered); cause != nil {
			fmt.Println(cause.Error())
		}
	}

	recovered = CreateComplexErrorWithNConsequences(1)
	if recovered != nil {
		if _, ok := recovered.(*ErrTimeout); !ok {
			t.Errorf("It should be a 'ErrTimeout', but it's instead a '%s'", reflect.TypeOf(recovered).String())
		}

		if cause := fail.Cause(recovered); cause != nil {
			if _, ok := cause.(*fail.ErrNotFound); !ok {
				t.Errorf(
					"It should be a 'fail.ErrNotFound', but it's instead a '%s'", reflect.TypeOf(recovered).String(),
				)
			}
		}
	}
}

func TestSkipRetries(t *testing.T) {
	recovered := CreateSkippableError()
	if recovered != nil {
		if _, ok := recovered.(*ErrTimeout); ok {
			t.Errorf("It should NOT be a 'ErrTimeout', it's instead a '%s'", reflect.TypeOf(recovered).String())
		}

		if cause := fail.Cause(recovered); cause != nil {
			if _, ok := cause.(*fail.ErrNotFound); ok {
				fmt.Println(cause.Error())
			} else {
				t.Errorf("This should be a 'fail.ErrNotFound', it's instead a '%s'", reflect.TypeOf(cause).String())
			}
		}
	}
}

func TestSkipRetriesBis(t *testing.T) {
	recovered := CreateSkippableErrorBis()
	if recovered != nil {
		if _, ok := recovered.(*ErrTimeout); ok {
			t.Errorf("It should NOT be a 'ErrTimeout', it's instead a '%s'", reflect.TypeOf(recovered).String())
		}

		if cause := fail.Cause(recovered); cause != nil {
			if _, ok := cause.(*fail.ErrNotFound); ok {
				fmt.Println(cause.Error())
			} else {
				t.Errorf("This should be a 'fail.ErrNotFound', it's instead a '%s'", reflect.TypeOf(cause).String())
			}
		}
	}
}

func TestAddingConsequencesToABasicError(t *testing.T) {
	recovered := JustThrowBasicError()
	if recovered != nil {
		recovered = fail.AddConsequence(recovered, fmt.Errorf("another mishap"))
		cons := fail.Consequences(recovered)
		if len(cons) != 0 {
			t.Errorf("This error should have NO consequences because it's a basic error...")
		}
	}
}

func TestConsequence(t *testing.T) {
	recovered := CreateErrorWithNConsequences(1)
	if recovered != nil {
		cons := fail.Consequences(recovered)
		if len(cons) == 0 {
			t.Errorf("This error should have consequences...")
		}
	}

	recovered = CreateErrorWithNConsequences(0)
	if recovered != nil {
		cons := fail.Consequences(recovered)
		if len(cons) != 0 {
			t.Errorf("This error should have NO consequences...")
		}
	}

	recovered = JustThrowError()
	if recovered != nil {
		_ = recovered.AddConsequence(fmt.Errorf("another disgrace"))
		cons := fail.Consequences(recovered)
		if len(cons) == 0 {
			t.Errorf("This error should have consequences...")
		}
	}

	recovered = JustThrowComplexError()
	if recovered != nil {
		cons := fail.Consequences(recovered)
		if len(cons) == 0 {
			t.Errorf("This error should have consequences...")
		}
	}
}

func TestDeferredConsequence(t *testing.T) {
	recovered := CreateDeferredErrorWithNConsequences(1)
	if recovered != nil {
		cons := fail.Consequences(recovered)
		if len(cons) == 0 {
			t.Errorf("This error should have consequences...")
		} else {
			for _, con := range cons {
				fmt.Println(con)
			}
		}
	}

	recovered = CreateDeferredErrorWithNConsequences(0)
	if recovered != nil {
		cons := fail.Consequences(recovered)
		if len(cons) != 0 {
			t.Errorf("This error should have NO consequences...")
		}
	}
}

func TestDeferredConsequenceText(t *testing.T) {
	recovered := CreateDeferredErrorWithNConsequences(2)
	if recovered != nil {
		cons := fail.Consequences(recovered)
		if len(cons) == 0 {
			t.Errorf("This error should have consequences...")
		} else {
			for _, con := range cons {
				fmt.Println(con)
			}
		}
		fmt.Println(recovered.Error())
	}
}

func TestWhileUnsuccessfulDelay5Seconds(t *testing.T) {
	type args struct {
		run     func() error
		timeout time.Duration
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"OneTimeSlowOK", args{sleepy, time.Duration(15) * 10 * time.Millisecond}, true},
		{"OneTimeSlowFails", args{sleepyFailure, time.Duration(15) * 10 * time.Millisecond}, true},
		{"OneTimeQuickOK", args{quickSleepy, time.Duration(15) * 10 * time.Millisecond}, false},
		{"UntilTimeouts", args{quickSleepyFailure, time.Duration(15) * 10 * time.Millisecond}, true},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				if err := WhileUnsuccessfulDelay50ms(tt.args.run, tt.args.timeout); (err != nil) != tt.wantErr {
					t.Errorf("WhileUnsuccessfulDelay50ms() error = %v, wantErr %v", err, tt.wantErr)
				}
			},
		)
	}
}

func TestWhileUnsuccessfulDelay5SecondsCheck(t *testing.T) {
	type args struct {
		run     func() error
		timeout time.Duration
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantTOErr bool
	}{
		{"OneTimeSlowOK", args{sleepy, time.Duration(15) * 10 * time.Millisecond}, true, true},
		{"OneTimeSlowFails", args{sleepyFailure, time.Duration(15) * 10 * time.Millisecond}, true, true},
		{"OneTimeQuickOK", args{quickSleepy, time.Duration(15) * 10 * time.Millisecond}, false, false},
		{"UntilTimeouts", args{quickSleepyFailure, time.Duration(15) * 10 * time.Millisecond}, true, true},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				testStart := time.Now()
				var err error
				if err = WhileUnsuccessfulDelay50ms(tt.args.run, tt.args.timeout); (err != nil) != tt.wantErr {
					t.Errorf("WhileUnsuccessfulDelay50ms() error = %v, wantErr %v", err, tt.wantErr)
				}
				if err != nil {
					if tt.wantTOErr {
						if _, ok := err.(*ErrTimeout); !ok {
							t.Errorf("'ErrTimeout' not received...")
						}
					}
				}
				delta := time.Since(testStart)
				if delta.Seconds() >= tt.args.timeout.Seconds()+2 && !tt.wantTOErr {
					t.Errorf(
						"WhileUnsuccessfulDelay50ms() error = %v", fmt.Errorf(
							"it's not a real timeout, il tasted %f and the limit was %f", delta.Seconds(),
							tt.args.timeout.Seconds(),
						),
					)
				}
			},
		)
	}
}

func WhileUnsuccessfulDelay50msSecondsTimeout(run func() error, timeout time.Duration) error {
	return WhileUnsuccessfulWithHardTimeout(run, 50*time.Millisecond, timeout)
}

func WhileUnsuccessfulDelay50ms(run func() error, timeout time.Duration) error {
	return WhileUnsuccessful(run, 50*time.Millisecond, timeout)
}

func TestWhileUnsuccessfulDelay5SecondsCheckStrictTimeout(t *testing.T) {
	type args struct {
		run     func() error
		timeout time.Duration
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantTOErr bool
	}{
		{"OneTimeSlowOK", args{sleepy, time.Duration(15) * 10 * time.Millisecond}, true, false},
		{"OneTimeSlowFails", args{sleepyFailure, time.Duration(15) * 10 * time.Millisecond}, true, false},
		{"OneTimeQuickOK", args{quickSleepy, time.Duration(15) * 10 * time.Millisecond}, false, false},
		{"UntilTimeouts", args{quickSleepyFailure, time.Duration(15) * 10 * time.Millisecond}, true, false},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				testStart := time.Now()
				var err error
				if err = WhileUnsuccessfulDelay50msSecondsTimeout(
					tt.args.run, tt.args.timeout,
				); (err != nil) != tt.wantErr {
					t.Errorf("WhileUnsuccessfulDelay50msSecondsTimeout() error = %v, wantErr %v", err, tt.wantErr)
				}
				if err != nil {
					if tt.wantTOErr {
						if _, ok := err.(*ErrTimeout); !ok {
							t.Errorf("ErrTimeout error not received...")
						}
					}
				}
				delta := time.Since(testStart)
				if delta.Seconds() >= tt.args.timeout.Seconds()+1.5 { // 0.5 seconds tolerance
					t.Errorf(
						"WhileUnsuccessfulDelay50msSecondsTimeout() error = %v", fmt.Errorf(
							"it's not a real timeout, il tasted %f and the limit was %f", delta.Seconds(),
							tt.args.timeout.Seconds(),
						),
					)
				}
			},
		)
	}
}

func genErr() error {
	return abstract.ResourceNotFoundError("host", "whatever")
}

func genTimeout() error {
	return TimeoutError(fmt.Errorf("too late ... "), 10*time.Millisecond, 30*time.Millisecond)
}

func genLimit() error {
	return LimitError(fmt.Errorf("7 times is one too many"), 7)
}

func genAbort() error {
	return StopRetryError(fmt.Errorf("4hJx7NGwyH7dPGQNY3WG happened !! "), "weird provider error")
}

func TestErrorHierarchy(t *testing.T) {
	nerr := genErr()
	if _, ok := nerr.(*fail.ErrNotFound); !ok {
		t.Errorf("Is not a 'ErrNotFound', it's instead a '%s'", reflect.TypeOf(nerr).String())
	}
}

func TestKeepType(t *testing.T) {
	toe := genTimeout()
	if _, ok := toe.(*ErrTimeout); !ok {
		t.Errorf("Is not a 'ErrTimeout', it's instead a '%s'", reflect.TypeOf(toe).String())
	}

	leo := genLimit()
	if _, ok := leo.(*ErrLimit); !ok {
		t.Errorf("Is not a 'ErrLimit', it's instead a '%s'", reflect.TypeOf(leo).String())
	}

	abo := genAbort()
	if _, ok := abo.(*ErrStopRetry); !ok {
		t.Errorf("Is not a 'ErrStopRetry', it's instead a '%s'", reflect.TypeOf(abo).String())
	}
}

func TestRefactorSwitch(t *testing.T) {
	toe := genTimeout()

	switch toe.(type) {
	case ErrTimeout:
		fmt.Println("This requires looking for all the (type) out there...")
	case *ErrTimeout:
		fmt.Println("Good enough")
	default:
		t.Error("Unexpected problem")
	}
}

func genHappy() error {
	return nil
}

func genSad() error {
	provErr := fail.NotFoundError("The resource %s is not there", "whatever")
	interlude := fail.AbortedError(provErr, "we had to abort")
	endGame := fmt.Errorf("this is sad: %w", interlude)
	return endGame
}

func genHandledPanic() error {
	provErr := fail.NotFoundError("The resource %s is not there", "whatever")
	interlude := fail.AbortedError(provErr, "we had to abort, we didn't know what to do without the resource")
	endGame := fail.RuntimePanicError("thank god we caught this on time: %w", interlude)
	return endGame
}

func genAbortedError() error {
	provErr := fail.NotFoundError("The resource %s is not there", "whatever")
	endGame := fail.AbortedError(provErr, "we had to abort, we didn't know what to do without the resource")
	return endGame
}

func TestErrCheckTimeout(t *testing.T) {
	// This HAS to timeout after 5 seconds because genHappy never fails,
	// so xerr at the end should be some kind of timeoutError
	xerr := WhileSuccessful(
		func() error {
			innerXErr := genHappy()
			return innerXErr
		},
		50*time.Millisecond,
		1*time.Second,
	)
	if xerr == nil {
		t.Errorf("the while.. HAS to fail")
		t.FailNow()
	}
	if _, ok := xerr.(*fail.ErrTimeout); !ok {
		t.Errorf("the error HAS to be a timeout")
		t.FailNow()
	}
	reason := fail.Cause(xerr)
	if reason == nil {
		t.Errorf("it MUST have a cause")
		t.FailNow()
	}

	// Now we even have the root reason, if any
	if !strings.Contains(reason.Error(), "timed out after") {
		t.Errorf("the text MUST contain 'timed out after'")
		t.FailNow()
	}
}

func TestErrCheckStopStdError(t *testing.T) {
	iteration := 0
	var errCause error
	xerr := WhileUnsuccessful(
		func() error {
			iteration++
			if iteration == 4 {
				return StopRetryError(fail.NewError("It failed at iteration #%d", iteration), "last error before stopping retries was")
			}
			return fail.NewError("It failed at iteration #%d", iteration)
		},
		10*time.Millisecond,
		60*time.Millisecond,
	)
	if xerr != nil {
		errCause = fail.RootCause(xerr)
		xerr = fail.Wrap(xerr, "the checking failed")
		t.Logf(xerr.Error())
		if !strings.Contains(xerr.Error(), "failed at iteration #4") {
			t.FailNow()
		}
	}

	if errCause != nil {
		t.Logf(errCause.Error())
		if !strings.Contains(errCause.Error(), "failed at iteration #4") {
			t.FailNow()
		}
	}
}

func TestErrCheckAbortedNoTimeout(t *testing.T) {
	// This doesn't end in timeout, because we send a panic, but we should be able to track its origin...
	xerr := WhileUnsuccessful(
		func() error {
			innerXErr := genAbortedError()
			return innerXErr
		},
		time.Second,
		5*time.Second,
	)
	if xerr == nil {
		t.Errorf("the while.. HAS to fail")
		t.FailNow()
	}
	if _, ok := xerr.(*fail.ErrAborted); !ok {
		t.Errorf("the error HAS to be an abortion")
		t.FailNow()
	}

	reason := fail.Cause(xerr)
	if reason == nil {
		t.Errorf("it MUST have a cause")
		t.FailNow()
	}
	if _, ok := reason.(*fail.ErrNotFound); !ok {
		t.Errorf("the cause MUST be a ErrNotFound")
		t.FailNow()
	}

	// Now we even have the root reason, if any
	if !strings.Contains(reason.Error(), "whatever") {
		t.Errorf("the text MUST contain whatever")
		t.FailNow()
	}
}

func TestErrCheckPanicNoTimeout(t *testing.T) {
	// This doesn't end in timeout, because we send an abortion, but we should be able to track its origin...
	// previous test, TestErrCheckAbortedNoTimeout, works as expected, this does not
	xerr := WhileUnsuccessful(
		func() error {
			innerXErr := genHandledPanic()
			return innerXErr
		},
		time.Second,
		5*time.Second,
	)
	if xerr == nil {
		t.Errorf("the while.. HAS to fail")
		t.FailNow()
	}
	if _, ok := xerr.(*fail.ErrRuntimePanic); !ok {
		t.Errorf("the error HAS to be a panic")
		t.FailNow()
	}

	reason := fail.RootCause(xerr)
	if reason == nil {
		t.Errorf("it MUST have a cause")
		t.FailNow()
	}
	if _, ok := reason.(*fail.ErrNotFound); !ok {
		t.Errorf("the cause MUST be a ErrNotFound")
		t.FailNow()
	}

	// Now we even have the root reason, if any
	if !strings.Contains(reason.Error(), "whatever") {
		t.Errorf("the text MUST contain whatever")
		t.FailNow()
	}
}

func TestErrCheckNoTimeout(t *testing.T) {
	// This HAS to timeout after 5 seconds because genSad always fails,
	// so xerr at the end should be some kind of timeoutError
	xerr := WhileUnsuccessful(
		func() error {
			innerXErr := genSad()
			return innerXErr
		},
		50*time.Millisecond,
		1*time.Second,
	)
	if xerr == nil {
		t.Errorf("the while.. HAS to fail")
		t.FailNow()
	}
	if _, ok := xerr.(*fail.ErrTimeout); !ok {
		t.Errorf("the error HAS to be a timeout")
		t.FailNow()
	}

	reason := fail.RootCause(xerr)
	if reason == nil {
		t.Errorf("it MUST have a cause")
		t.FailNow()
	}

	otherReason := fail.Cause(xerr)
	if _, ok := otherReason.(fail.Error); ok {
		t.Errorf("the cause MUST be a wrap, here it's not: %v", otherReason)
		t.FailNow()
	}

	// Now we even have the root reason, if any
	if !strings.Contains(reason.Error(), "whatever") {
		t.Errorf("the text MUST contain whatever")
		t.FailNow()
	}
}

func TestRetriesHitFirst(t *testing.T) {
	// This HAS to timeout after 3 retries before we hit the timeout
	// so xerr at the end should be some kind of OverflowError
	xerr := WhileUnsuccessfulWithLimitedRetries(
		func() error {
			innerXErr := genSad()
			return innerXErr
		},
		1*time.Second,
		5*time.Second,
		3,
	)
	if xerr == nil {
		t.FailNow()
	}
	if _, ok := xerr.(*fail.ErrOverflow); !ok {
		t.FailNow()
	}

	reason := fail.Cause(xerr)
	if reason == nil {
		t.FailNow()
	}

	// Now we even have the root reason, if any
	if !strings.Contains(reason.Error(), "whatever") {
		t.FailNow()
	}
}

// notice how this test and the next have the same results, problem is they shouldn't
func TestCustomActionWithTimeout(t *testing.T) {
	begin := time.Now()
	xerr := Action(
		genHappy,
		PrevailRetry(Successful(), Timeout(1*time.Second)),
		Constant(500*time.Millisecond),
		nil, nil, nil,
	)
	if xerr == nil {
		t.FailNow()
	}
	if _, ok := xerr.(*fail.ErrTimeout); !ok {
		t.Errorf("the error HAS to be a timeout")
		t.FailNow()
	}

	delta := time.Since(begin)
	if delta < 1*time.Second {
		t.Errorf("retry timing didn't work well")
		t.FailNow()
	}
}

// notice how this test and the previous have the same results, problem is it shouldn't
func TestOtherCustomActionWithTimeout(t *testing.T) {
	begin := time.Now()
	xerr := Action(
		genHappy,
		PrevailRetry(Unsuccessful(), Timeout(6*time.Second)),
		Constant(1*time.Second),
		nil, nil, nil,
	)
	if xerr != nil {
		t.Errorf("It shouln't fail nor retry")
		t.FailNow()
	}

	delta := time.Since(begin)
	if delta > 2*time.Second {
		t.Errorf("There was a retry and it should have been none, timeout shoudn't be able to dictate when the retry finishes")
		t.FailNow()
	}
}

func TestDontComplainWhenWeHaveATimeoutButItsOK(t *testing.T) {
	begin := time.Now()

	xerr := WhileUnsuccessfulWithAggregator(
		func() error {
			time.Sleep(400 * time.Millisecond)
			return genHappy()
		},
		50*time.Millisecond,
		300*time.Millisecond,
		OrArbiter,
		func(t Try, v verdict.Enum) {
			if v == verdict.Retry {
				logrus.Infof("Oh la la la")
			}
		},
	)
	if xerr != nil {
		t.Errorf("It shouln't fail nor retry: %v", xerr)
		t.FailNow()
	}

	delta := time.Since(begin)
	if delta > 450*time.Millisecond {
		t.Errorf("There was a retry and it should have been none, timeout shoudn't be able to dictate when the retry finishes")
		t.FailNow()
	}
}

func TestRepeat(at *testing.T) {
	chErr := make(chan error)
	go func() {
		for { // the end of test kills this
			num := mrand.Intn(123)
			if num > 3 {
				chErr <- fmt.Errorf("ouch")
			} else {
				chErr <- nil
			}
		}
	}()

	iterations := 0
	innerIterations := 0

	// Outer retry will write the metadata at most 3 times
	xerr := Action(
		func() error {
			iterations++

			// inner retry does read-after-write; if timeout consider write has failed, then retry write
			innerXErr := Action(
				func() error {
					innerIterations++

					innerErr := <-chErr
					if innerErr != nil {
						return innerErr
					}

					return nil
				},
				PrevailDone(Unsuccessful(), Timeout(300), Max(3)),
				Linear(1),
				nil,
				nil,
				func(t Try, v verdict.Enum) {
					switch v { // nolint
					case verdict.Retry:
						at.Log("Retrying...")
					default:
						at.Logf("%v", v)
					}
				},
			)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *ErrStopRetry, *ErrTimeout:
					return fail.Wrap(innerXErr.Cause(), "stopping retries: %d, %d", iterations, innerIterations)
				default:
					return innerXErr
				}
			}
			return nil
		},
		PrevailDone(Unsuccessful(), Max(6)),
		Constant(0),
		nil,
		nil,
		func(t Try, v verdict.Enum) {
			switch v { // nolint
			case verdict.Retry:
				at.Log("External Retrying...")
			}
		},
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *ErrTimeout:
			at.Log(xerr)
		case *ErrStopRetry:
			at.Log(xerr)
		default:
			at.Log(xerr)
		}
	}
}

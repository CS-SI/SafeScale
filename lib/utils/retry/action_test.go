/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

func quick_sleepy() error {
	fmt.Println("Quick OK")
	time.Sleep(1 * 10 * time.Millisecond)
	return nil
}

func sleepy() error {
	fmt.Println("Slow OK")
	time.Sleep(1 * 60 * 10 * time.Millisecond)
	return nil
}

func sleepy_failure() error {
	fmt.Println("Slow fail")
	time.Sleep(1 * 60 * 10 * time.Millisecond)
	return fmt.Errorf("always fails")
}

func quick_sleepy_failure() error {
	fmt.Println("Quick fail")
	time.Sleep(1 * 10 * time.Millisecond)
	return fmt.Errorf("always fails")
}

func complex_sleepy_failure() error {
	fmt.Println("Quick fail")
	time.Sleep(1 * 10 * time.Millisecond)
	return scerr.NotFoundError("Not here")
}

func CreateErrorWithNConsequences(n uint) (err error) {
	err = WhileUnsuccessfulDelay1Second(quick_sleepy_failure, time.Duration(5)*10*time.Millisecond)
	if err != nil {
		for loop := uint(0); loop < n; loop++ {
			nerr := fmt.Errorf("random cleanup problem")
			err = scerr.AddConsequence(err, nerr)
		}
	}
	return err
}

func CreateSkippableError() (err error) {
	err = WhileSuccessfulDelay1Second(func() error {
		fmt.Println("Around the world...")
		return AbortedError("no more", scerr.NotFoundError("wrong place"))
	}, 60*time.Millisecond)
	return err
}

func CreateComplexErrorWithNConsequences(n uint) (err error) {
	err = WhileUnsuccessfulDelay1Second(complex_sleepy_failure, time.Duration(5)*10*time.Millisecond)
	if err != nil {
		for loop := uint(0); loop < n; loop++ {
			nerr := fmt.Errorf("random cleanup problem")
			err = scerr.AddConsequence(err, nerr)
		}
	}
	return err
}

func JustThrowBasicError() (err error) {
	return fmt.Errorf("something happened")
}

func JustThrowError() (err error) {
	return resources.ResourceDuplicateError("host", "boo")
}

func JustThrowComplexError() (err error) {
	err = resources.ResourceDuplicateError("host", "booboo")
	err = scerr.AddConsequence(err, fmt.Errorf("cleanup error"))
	return err
}

func CreateDeferredErrorWithNConsequences(n uint) (err error) {
	defer func() {
		if err != nil {
			for loop := uint(0); loop < n; loop++ {
				nerr := fmt.Errorf("random cleanup problem")
				err = scerr.AddConsequence(err, nerr)
			}
		}
	}()

	err = WhileUnsuccessfulDelay1Second(quick_sleepy_failure, time.Duration(5)*10*time.Millisecond)
	return err
}

func CreateWrappedDeferredErrorWithNConsequences(n uint) (err error) {
	defer func() {
		if err != nil {
			for loop := uint(0); loop < n; loop++ {
				nerr := fmt.Errorf("random cleanup problem")
				err = scerr.AddConsequence(err, nerr)
			}
		}
	}()

	err = WhileUnsuccessfulDelay1Second(quick_sleepy_failure, time.Duration(5)*10*time.Millisecond)
	return err
}

func TestDeferredWrappedConsequence(t *testing.T) {
	recovered := CreateWrappedDeferredErrorWithNConsequences(1)
	if recovered != nil {
		cons := scerr.Consequences(recovered)
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
		if _, ok := recovered.(*scerr.ErrTimeout); !ok {
			t.Errorf("It should be a timeout, but it's [%s]", reflect.TypeOf(recovered).String())
		}

		if cause := scerr.Cause(recovered); cause != nil {
			fmt.Println(cause.Error())
		}
	}

	recovered = CreateComplexErrorWithNConsequences(1)
	if recovered != nil {
		if _, ok := recovered.(*scerr.ErrTimeout); !ok {
			t.Errorf("It should be a timeout, but it's [%s]", reflect.TypeOf(recovered).String())
		}

		if cause := scerr.Cause(recovered); cause != nil {
			if _, ok := cause.(*scerr.ErrNotFound); !ok {
				t.Errorf("It should be a ErrNotFound, but it's [%s]", reflect.TypeOf(recovered).String())
			}
		}
	}
}

func TestSkipRetries(t *testing.T) {
	recovered := CreateSkippableError()
	if recovered != nil {
		if _, ok := recovered.(*scerr.ErrTimeout); ok {
			t.Errorf("It should NOT be a timeout, but it's [%s]", reflect.TypeOf(recovered).String())
		}

		if cause := scerr.Cause(recovered); cause != nil {
			if _, ok := cause.(*scerr.ErrNotFound); ok {
				fmt.Println(cause.Error())
			} else {
				t.Errorf("This should be a NotFound error...")
			}
		}
	}
}

func TestAddingConsequencesToABasicError(t *testing.T) {
	recovered := JustThrowBasicError()
	if recovered != nil {
		recovered = scerr.AddConsequence(recovered, fmt.Errorf("another mishap"))
		cons := scerr.Consequences(recovered)
		if len(cons) != 0 {
			t.Errorf("This error should have NO consequences because it's a basic error...")
		}
	}
}

func TestConsequence(t *testing.T) {
	recovered := CreateErrorWithNConsequences(1)
	if recovered != nil {
		cons := scerr.Consequences(recovered)
		if len(cons) == 0 {
			t.Errorf("This error should have consequences...")
		}
	}

	recovered = CreateErrorWithNConsequences(0)
	if recovered != nil {
		cons := scerr.Consequences(recovered)
		if len(cons) != 0 {
			t.Errorf("This error should have NO consequences...")
		}
	}

	recovered = JustThrowError()
	if recovered != nil {
		recovered = scerr.AddConsequence(recovered, fmt.Errorf("another disgrace"))
		cons := scerr.Consequences(recovered)
		if len(cons) == 0 {
			t.Errorf("This error should have consequences...")
		}
	}

	recovered = JustThrowComplexError()
	if recovered != nil {
		cons := scerr.Consequences(recovered)
		if len(cons) == 0 {
			t.Errorf("This error should have consequences...")
		}
	}
}

func TestDeferredConsequence(t *testing.T) {
	recovered := CreateDeferredErrorWithNConsequences(1)
	if recovered != nil {
		cons := scerr.Consequences(recovered)
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
		cons := scerr.Consequences(recovered)
		if len(cons) != 0 {
			t.Errorf("This error should have NO consequences...")
		}
	}
}

func TestDeferredConsequenceText(t *testing.T) {
	recovered := CreateDeferredErrorWithNConsequences(2)
	if recovered != nil {
		cons := scerr.Consequences(recovered)
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
		{"OneTimeSlowOK", args{sleepy, time.Duration(15) * 10 * time.Millisecond}, false},
		{"OneTimeSlowFails", args{sleepy_failure, time.Duration(15) * 10 * time.Millisecond}, true},
		{"OneTimeQuickOK", args{quick_sleepy, time.Duration(15) * 10 * time.Millisecond}, false},
		{"UntilTimeouts", args{quick_sleepy_failure, time.Duration(15) * 10 * time.Millisecond}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := WhileUnsuccessfulDelay50ms(tt.args.run, tt.args.timeout); (err != nil) != tt.wantErr {
				t.Errorf("WhileUnsuccessfulDelay50ms() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
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
		{"OneTimeSlowOK", args{sleepy, time.Duration(15) * 10 * time.Millisecond}, false, true},
		{"OneTimeSlowFails", args{sleepy_failure, time.Duration(15) * 10 * time.Millisecond}, true, true},
		{"OneTimeQuickOK", args{quick_sleepy, time.Duration(15) * 10 * time.Millisecond}, false, false},
		{"UntilTimeouts", args{quick_sleepy_failure, time.Duration(15) * 10 * time.Millisecond}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testStart := time.Now()
			var err error
			if err = WhileUnsuccessfulDelay50ms(tt.args.run, tt.args.timeout); (err != nil) != tt.wantErr {
				t.Errorf("WhileUnsuccessfulDelay50ms() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				if tt.wantTOErr {
					if _, ok := err.(*ErrTimeout); !ok {
						t.Errorf("Timeout error not received...")
					}
				}
			}
			delta := time.Since(testStart)
			if delta.Seconds() >= tt.args.timeout.Seconds()+2 && !tt.wantTOErr {
				t.Errorf("WhileUnsuccessfulDelay50ms() error = %v", fmt.Errorf("it's not a real timeout, il tasted %f and the limit was %f", delta.Seconds(), tt.args.timeout.Seconds()))
			}
		})
	}
}

func WhileUnsuccessfulDelay50msSecondsTimeout(run func() error, timeout time.Duration) error {
	return WhileUnsuccessfulTimeout(run, 50*time.Millisecond, timeout)
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
		{"OneTimeSlowFails", args{sleepy_failure, time.Duration(15) * 10 * time.Millisecond}, true, false},
		{"OneTimeQuickOK", args{quick_sleepy, time.Duration(15) * 10 * time.Millisecond}, false, false},
		{"UntilTimeouts", args{quick_sleepy_failure, time.Duration(15) * 10 * time.Millisecond}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testStart := time.Now()
			var err error
			if err = WhileUnsuccessfulDelay50msSecondsTimeout(tt.args.run, tt.args.timeout); (err != nil) != tt.wantErr {
				t.Errorf("WhileUnsuccessfulDelay50msSecondsTimeout() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				if tt.wantTOErr {
					if _, ok := err.(*ErrTimeout); !ok {
						t.Errorf("Timeout error not received...")
					}
				}
			}
			delta := time.Since(testStart)
			if delta.Seconds() >= tt.args.timeout.Seconds()+1.5 { // 0.5 seconds tolerance
				t.Errorf("WhileUnsuccessfulDelay50msSecondsTimeout() error = %v", fmt.Errorf("it's not a real timeout, il tasted %f and the limit was %f", delta.Seconds(), tt.args.timeout.Seconds()))
			}
		})
	}
}

func genErr() error {
	return resources.ResourceNotFoundError("host", "whatever")
}

func genTimeout() error {
	return TimeoutError(10*time.Millisecond, fmt.Errorf("too late..."))
}

func genLimit() error {
	return LimitError(7, fmt.Errorf("7 times is one too many"))
}

func genAbort() error {
	return AbortedError("bizarre provider error", fmt.Errorf("4hJx7NGwyH7dPGQNY3WG happened !!"))
}

func TestErrorHierarchy(t *testing.T) {
	nerr := genErr()

	if _, ok := nerr.(*scerr.ErrNotFound); !ok {
		t.Errorf("Is not a resourceNotFound")
	}
}

func TestKeepType(t *testing.T) {
	toe := genTimeout()
	if _, ok := toe.(*scerr.ErrTimeout); !ok {
		t.Errorf("Is not a timeout")
	}

	leo := genLimit()
	if _, ok := leo.(*scerr.ErrOverflow); !ok {
		t.Errorf("Is not a limit error")
	}

	abo := genAbort()
	if _, ok := abo.(*scerr.ErrAborted); !ok {
		t.Errorf("Is not a aborted")
	}
}

func TestRefactorSwitch(t *testing.T) {
	toe := genTimeout()

	switch toe.(type) {
	case ErrTimeout:
		t.Error("No longer a timeout")
	case *ErrTimeout:
		fmt.Println("This requires looking for all the (type) out there...")
	default:
		t.Error("Unexpected problem")
	}
}

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

// Package retry implements a mean to retry an action with ability to define complex
// delays and stop conditions

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/Verdict"
)

// Try keeps track of the number of tries, starting from 1. Action is valid only when Err is nil.
type Try struct {
	Start time.Time
	Count uint
	Err   error
}

type action struct {
	// Officer is used to apply needed delay between 2 tries. If nil, no delay will be used.
	Officer *Officer
	// Arbiter is called for every try to determine if next try is wanted
	Arbiter Arbiter
	// First is called before the loop of retries
	First func() error
	// Run is called for every try
	Run func() error
	// Last is called after the loop of retries (being successful or not)
	Last func() error
	// Notify
	Notify Notify
}

// Action tries to executes 'run' following verdicts from arbiter, with delay decided by 'officer'.
// If defined, 'first' is executed before trying (and may fail), and last is executed after the
// tries (whatever the state of the tries is, and can't fail)
func Action(run func() error, arbiter Arbiter, officer *Officer,
	first func() error, last func() error, notify Notify) error {

	if run == nil {
		panic("retry.Action(): run == nil!")
	}
	if arbiter == nil {
		panic("retry.Action(): arbiter == nil!")
	}
	if officer == nil {
		panic("retry.Action(): officer == nil!")
	}

	return action{
		Officer: officer,
		Arbiter: arbiter,
		First:   first,
		Last:    last,
		Run:     run,
		Notify:  notify,
	}.loop()

}

// WhileUnsuccessful retries every 'delay' while 'run' is unsuccessful with a 'timeout'
func WhileUnsuccessful(run func() error, delay time.Duration, timeout time.Duration) error {
	if delay > timeout {
		logrus.Warnf("unexpected: delay greater than timeout ?? : (%s) > (%s)", delay, timeout)
	}

	if delay <= 0 {
		delay = time.Second
	}
	var arbiter Arbiter
	if timeout <= 0 {
		arbiter = Unsuccessful()
	} else {
		arbiter = PrevailDone(Unsuccessful(), Timeout(timeout))
	}
	return action{
		Arbiter: arbiter,
		Officer: Constant(delay),
		Run:     run,
		First:   nil,
		Last:    nil,
		Notify:  nil,
	}.loop()
}

// WhileUnsuccessfulTimeout retries every 'delay' while 'run' is unsuccessful with a 'timeout'
func WhileUnsuccessfulTimeout(run func() error, delay time.Duration, timeout time.Duration) error {
	if delay > timeout {
		logrus.Warnf("unexpected: delay greater than timeout ?? : (%s) > (%s)", delay, timeout)
	}

	if delay <= 0 {
		delay = time.Second
	}
	var arbiter Arbiter
	if timeout <= 0 {
		arbiter = Unsuccessful()
	} else {
		arbiter = PrevailDone(Unsuccessful(), Timeout(timeout))
	}
	return action{
		Arbiter: arbiter,
		Officer: Constant(delay),
		Run:     run,
		First:   nil,
		Last:    nil,
		Notify:  nil,
	}.loopWithTimeout(timeout)
}

// WhileUnsuccessfulDelay1Second retries while 'run' is unsuccessful (ie 'run' returns an error != nil),
// waiting 1 second after each try, expiring after 'timeout'
func WhileUnsuccessfulDelay1Second(run func() error, timeout time.Duration) error {
	return WhileUnsuccessful(run, time.Second, timeout)
}

// WhileUnsuccessfulDelay5Seconds retries while 'run' is unsuccessful (ie 'run' returns an error != nil),
// waiting 5 seconds after each try, expiring after 'timeout'
func WhileUnsuccessfulDelay5Seconds(run func() error, timeout time.Duration) error {
	return WhileUnsuccessful(run, 5*time.Second, timeout)
}

// WhileUnsuccessfulDelay5SecondsTimeout ...
func WhileUnsuccessfulDelay5SecondsTimeout(run func() error, timeout time.Duration) error {
	return WhileUnsuccessfulTimeout(run, 5*time.Second, timeout)
}

// WhileUnsuccessfulWithNotify retries while 'run' is unsuccessful (ie 'run' returns an error != nil),
// waiting 'delay' after each try, expiring after 'timeout'
func WhileUnsuccessfulWithNotify(run func() error, delay time.Duration, timeout time.Duration, notify Notify) error {
	if delay > timeout {
		logrus.Warnf("unexpected: delay greater than timeout ?? : (%s) > (%s)", delay, timeout)
	}

	if notify == nil {
		panic("retry.WhileUnsuccessfulWithNotify(): notify == nil!")
	}

	if delay <= 0 {
		delay = time.Second
	}
	var arbiter Arbiter
	if timeout <= 0 {
		arbiter = Unsuccessful()
	} else {
		arbiter = PrevailDone(Unsuccessful(), Timeout(timeout))
	}
	return action{
		Arbiter: arbiter,
		Officer: Constant(delay),
		Run:     run,
		First:   nil,
		Last:    nil,
		Notify:  notify,
	}.loop()
}

// WhileUnsuccessfulWhereRetcode255WithNotify retries while 'run' is unsuccessful (ie 'run' returns an error != nil
// and this error has 255 as exit status code), waiting 'delay' after each try, expiting after 'timeout'
func WhileUnsuccessfulWhereRetcode255WithNotify(run func() error, delay time.Duration, timeout time.Duration, notify Notify) error {
	if delay > timeout {
		logrus.Warnf("unexpected: delay greater than timeout ?? : (%s) > (%s)", delay, timeout)
	}

	if notify == nil {
		panic("retry.WhileUnsuccessfulWithNotify(): notify == nil!")
	}

	if delay <= 0 {
		delay = time.Second
	}
	var arbiter Arbiter
	if timeout <= 0 {
		arbiter = UnsuccessfulWhereRetcode255()
	} else {
		arbiter = PrevailDone(UnsuccessfulWhereRetcode255(), Timeout(timeout))
	}
	return action{
		Arbiter: arbiter,
		Officer: Constant(delay),
		Run:     run,
		First:   nil,
		Last:    nil,
		Notify:  notify,
	}.loop()
}

// WhileUnsuccessfulDelay1SecondWithNotify retries while 'run' is unsuccessful (ie 'run' returns an error != nil),
// waiting 1 second after each try, expiring after a duration of 'timeout'.
// 'notify' is called after each try for feedback.
func WhileUnsuccessfulDelay1SecondWithNotify(run func() error, timeout time.Duration, notify Notify) error {
	return WhileUnsuccessfulWithNotify(run, time.Second, timeout, notify)
}

// WhileUnsuccessfulDelay5SecondsWithNotify retries while 'run' is unsuccessful (ie 'run' returns an error != nil),
// waiting 5 seconds after each try, expiring after a duration of 'timeout'.
// 'notify' is called after each try for feedback.
func WhileUnsuccessfulDelay5SecondsWithNotify(run func() error, timeout time.Duration, notify Notify) error {
	return WhileUnsuccessfulWithNotify(run, time.Second*5, timeout, notify)
}

// WhileUnsuccessfulWhereRetcode255Delay5SecondsWithNotify retries while 'run' is unsuccessful (ie 'run' returns an error != nil
// and this error has 255 as exit status code), waiting 5 seconds after each try, expiring after a duration of 'timeout'.
// 'notify' is called after each try for feedback.
func WhileUnsuccessfulWhereRetcode255Delay5SecondsWithNotify(run func() error, timeout time.Duration, notify Notify) error {
	return WhileUnsuccessfulWhereRetcode255WithNotify(run, time.Second*5, timeout, notify)
}

// WhileSuccessful retries while 'run' is successful (ie 'run' returns an error == nil),
// waiting a duration of 'delay' after each try, expiring after a duration of 'timeout'.
func WhileSuccessful(run func() error, delay time.Duration, timeout time.Duration) error {
	if delay > timeout {
		logrus.Warnf("unexpected: delay greater than timeout ?? : (%s) > (%s)", delay, timeout)
	}

	if delay <= 0 {
		delay = time.Second
	}
	var arbiter Arbiter
	if timeout <= 0 {
		arbiter = Successful()
	} else {
		arbiter = PrevailDone(Successful(), Timeout(timeout))
	}
	return action{
		Arbiter: arbiter,
		Officer: Constant(delay),
		Run:     run,
		First:   nil,
		Last:    nil,
		Notify:  nil,
	}.loop()
}

// WhileSuccessfulDelay1Second retries while 'run' is successful (ie 'run' returns an error == nil),
// waiting 1 second after each try, expiring after a duration of 'timeout'.
func WhileSuccessfulDelay1Second(run func() error, timeout time.Duration) error {
	return WhileSuccessful(run, time.Second, timeout)
}

// WhileSuccessfulDelay5Seconds retries while 'run' is successful (ie 'run' returns an error == nil),
// waiting 5 seconds after each try, expiring after a duration of 'timeout'.
func WhileSuccessfulDelay5Seconds(run func() error, timeout time.Duration) error {
	return WhileSuccessful(run, 5*time.Second, timeout)
}

// WhileSuccessfulWithNotify retries while 'run' is successful (ie 'run' returns an error == nil),
// waiting a duration of 'delay' after each try, expiring after a duration of 'timeout'.
// 'notify' is called after each try for feedback.
func WhileSuccessfulWithNotify(run func() error, delay time.Duration, timeout time.Duration, notify Notify) error {
	if delay > timeout {
		logrus.Warnf("unexpected: delay greater than timeout ?? : (%s) > (%s)", delay, timeout)
	}

	if notify == nil {
		panic("notify == nil!")
	}

	if delay <= 0 {
		delay = time.Second
	}
	var arbiter Arbiter
	if timeout <= 0 {
		arbiter = Successful()
	} else {
		arbiter = PrevailDone(Successful(), Timeout(timeout))
	}
	return action{
		Arbiter: arbiter,
		Officer: Constant(delay),
		Run:     run,
		First:   nil,
		Last:    nil,
		Notify:  notify,
	}.loop()
}

// WhileSuccessfulDelay1SecondWithNotify retries while 'run' is successful (ie 'run' returns an error == nil),
// waiting 1 second after each try, expiring after a duration of 'timeout'.
// 'notify' is called after each try for feedback.
func WhileSuccessfulDelay1SecondWithNotify(run func() error, timeout time.Duration, notify Notify) error {
	return WhileSuccessfulWithNotify(run, time.Second, timeout, notify)
}

// WhileSuccessfulDelay5SecondsWithNotify retries while 'run' is successful (ie 'run' returns an error == nil),
// waiting 5 seconds after each try, expiring after a duration of 'timeout'.
// 'notify' is called after each try for feedback.
func WhileSuccessfulDelay5SecondsWithNotify(run func() error, timeout time.Duration, notify Notify) error {
	return WhileSuccessfulWithNotify(run, 5*time.Second, timeout, notify)
}

// loop executes the tries
func (a action) loop() error {
	var (
		arbiter = a.Arbiter
		start   = time.Now()
	)
	if arbiter == nil {
		arbiter = DefaultArbiter
	}

	if a.First != nil {
		err := a.First()
		if err != nil {
			return err
		}
	}

	for count := uint(1); ; count++ {
		// Perform action
		err := a.Run()

		// Collects the result of the try
		try := Try{
			Start: start,
			Count: count,
			Err:   err,
		}

		// Asks what to do now
		verdict, retryErr := arbiter(try)

		// Notify to interested parties
		if a.Notify != nil {
			a.Notify(try, verdict)
		}

		switch verdict {
		case Verdict.Done:
			// Returns the error if no retry is wanted
			var errLast error
			if a.Last != nil {
				errLast = a.Last()
			}
			if errLast != nil {
				return fmt.Errorf("%s + %s", err.Error(), errLast.Error())
			}
			return err
		case Verdict.Abort:
			// Abort wanted, returns an error explaining why
			var errLast error
			if a.Last != nil {
				errLast = a.Last()
			}
			if errLast != nil {
				return fmt.Errorf("%s + %s", retryErr.Error(), errLast.Error())
			}
			return retryErr
		default:
			// Retry is wanted, so blocks the loop the amount of time needed
			if a.Officer != nil {
				a.Officer.Block(try)
			}
		}
	}
}

// loop executes the tries
func (a action) loopWithTimeout(timeout time.Duration) error {
	var (
		arbiter = a.Arbiter
		start   = time.Now()
	)
	if arbiter == nil {
		arbiter = DefaultArbiter
	}

	if a.First != nil {
		err := a.First()
		if err != nil {
			return err
		}
	}

	desist := time.After(timeout)
	for count := uint(1); ; count++ {
		var err error

		// Perform action
		ch := make(chan error)
		go func() {
			ch <- a.Run()
		}()

		select {
		case response := <-ch:
			err = response
		case <-time.After(timeout):
			// call timed out
			err = fmt.Errorf("operation timeout")
		case <-desist:
			err = fmt.Errorf("desist timeout")
		}

		// Collects the result of the try
		try := Try{
			Start: start,
			Count: count,
			Err:   err,
		}

		// Asks what to do now
		verdict, retryErr := arbiter(try)
		if a.Notify != nil {
			a.Notify(try, verdict)
		}

		switch verdict {
		case Verdict.Done:
			// Returns the error if no retry is wanted
			var errLast error
			if a.Last != nil {
				errLast = a.Last()
			}
			if errLast != nil {
				return fmt.Errorf("%s + %s", err.Error(), errLast.Error())
			}
			return err
		case Verdict.Abort:
			// Abort wanted, returns an error explaining why
			var errLast error
			if a.Last != nil {
				errLast = a.Last()
			}
			if errLast != nil {
				return fmt.Errorf("%s + %s", retryErr.Error(), errLast.Error())
			}
			return retryErr
		default:
			// Retry is wanted, so blocks the loop the amount of time needed
			if a.Officer != nil {
				go func() {
					a.Officer.Block(try)
					ch <- nil
				}()

				select {
				case response := <-ch:
					err = response
					_ = err
				case <-desist:
					err = fmt.Errorf("desist timeout")
					_ = err
				}
			}
		}
	}
}

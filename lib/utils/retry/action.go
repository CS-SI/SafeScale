/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"
	"os"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const minNumRetries = 3

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
	// Run is called for every try
	Run func() error
	// Notify
	Notify Notify
	// Timeout if any
	Timeout time.Duration
}

// Action tries to executes 'run' following verdicts from arbiter, with delay decided by 'officer'.
// If defined, 'first' is executed before trying (and may fail), and last is executed after the
// tries (whatever the state of the tries is, and cannot fail)
func Action(
	run func() error,
	arbiter Arbiter,
	officer *Officer,
	first func() error,
	last func() error,
	notify Notify,
) fail.Error {

	if run == nil {
		return fail.InvalidParameterError("run", "cannot be nil!")
	}
	if arbiter == nil {
		return fail.InvalidParameterError("arbiter", "cannot be nil!")
	}
	if officer == nil {
		return fail.InvalidParameterError("officer", "cannot be nil!")
	}

	selector := DefaultTimeoutSelector()
	return selector(action{
		Officer: officer,
		Arbiter: arbiter,
		Run:     run,
		Notify:  notify,
	})
}

func TimeoutSelector(hard bool) func(action) fail.Error {
	if hard {
		return action.loopWithHardTimeout
	}
	return action.loopWithSoftTimeout
}

func DefaultTimeoutSelector() func(action) fail.Error {
	if delayAlgo := os.Getenv("SAFESCALE_TIMEOUT_STYLE"); delayAlgo != "" {
		switch delayAlgo {
		case "Hard":
			return TimeoutSelector(true)
		case "Soft":
			return TimeoutSelector(false)
		default:
			return TimeoutSelector(false)
		}
	}

	return TimeoutSelector(false)
}

func BackoffSelector() Backoff {
	if delayAlgo := os.Getenv("SAFESCALE_ALGO_DELAY"); delayAlgo != "" {
		switch delayAlgo {
		case "Constant":
			return Constant
		case "Incremental":
			return Incremental
		case "Linear":
			return Linear
		case "Exponential":
			return Exponential
		case "Fibonacci":
			return Fibonacci
		default:
			return Constant
		}
	}

	return Constant
}

// WhileUnsuccessful retries every 'delay' while 'run' is unsuccessful with a 'timeout'
func WhileUnsuccessful(run func() error, delay time.Duration, timeout time.Duration) fail.Error {
	if delay > timeout {
		logrus.Warnf("unexpected parameters: 'delay' greater than 'timeout' ?? : (%s) > (%s)", delay, timeout)
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

	selector := DefaultTimeoutSelector()
	return selector(action{
		Arbiter: arbiter,
		Officer: BackoffSelector()(delay),
		Run:     run,
		Notify:  nil,
		Timeout: timeout,
	})
}

func WhileUnsuccessfulWithLimitedRetries(run func() error, delay time.Duration, timeout time.Duration, retries uint) fail.Error {
	if delay > timeout {
		logrus.Warnf("unexpected parameters: 'delay' greater than 'timeout' ?? : (%s) > (%s)", delay, timeout)
	}

	if delay <= 0 {
		delay = time.Second
	}
	var arbiter Arbiter
	if timeout <= 0 {
		if retries >= 1 {
			arbiter = PrevailDone(Unsuccessful(), Max(retries))
		} else {
			arbiter = Unsuccessful()
		}
	} else {
		if retries >= 1 {
			arbiter = PrevailDone(Unsuccessful(), Timeout(timeout), Max(retries))
		} else {
			arbiter = PrevailDone(Unsuccessful(), Timeout(timeout))
		}
	}
	selector := DefaultTimeoutSelector()
	return selector(action{
		Arbiter: arbiter,
		Officer: BackoffSelector()(delay),
		Run:     run,
		Notify:  nil,
		Timeout: timeout,
	})
}

// WhileUnsuccessfulWithHardTimeout retries every 'delay' while 'run' is unsuccessful with a 'timeout'
func WhileUnsuccessfulWithHardTimeout(run func() error, delay time.Duration, timeout time.Duration) fail.Error {
	if delay > timeout {
		logrus.Warnf("unexpected parameters: 'delay' greater than 'timeout' ?? : (%s) > (%s)", delay, timeout)
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
		Officer: BackoffSelector()(delay),
		Run:     run,
		Notify:  DefaultNotifier(),
		Timeout: timeout,
	}.loopWithHardTimeout()
}

// WhileUnsuccessfulWithHardTimeoutWithNotifier retries every 'delay' while 'run' is unsuccessful with a 'timeout'
func WhileUnsuccessfulWithHardTimeoutWithNotifier(run func() error, delay time.Duration, timeout time.Duration, notify Notify) fail.Error {
	if delay > timeout {
		logrus.Warnf("unexpected parameters: 'delay' greater than 'timeout' ?? : (%s) > (%s)", delay, timeout)
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
		Officer: BackoffSelector()(delay),
		Run:     run,
		Notify:  notify,
		Timeout: timeout,
	}.loopWithHardTimeout()
}

// WhileUnsuccessfulWithNotify retries while 'run' is unsuccessful (ie 'run' returns an error != nil),
// waiting 'delay' after each try, expiring after 'timeout'
func WhileUnsuccessfulWithNotify(run func() error, delay time.Duration, timeout time.Duration, notify Notify) fail.Error {
	if delay > timeout {
		logrus.Warnf("unexpected parameters: 'delay' greater than 'timeout' ?? : (%s) > (%s)", delay, timeout)
		delay = timeout / 2
	}

	if notify == nil {
		return fail.InvalidParameterError("notify", "cannot be nil!")
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
	selector := DefaultTimeoutSelector()
	return selector(action{
		Arbiter: arbiter,
		Officer: BackoffSelector()(delay),
		Run:     run,
		Notify:  notify,
		Timeout: timeout,
	})
}

// WhileUnsuccessfulWhereRetcode255WithNotify retries while 'run' is unsuccessful (ie 'run' returns an error != nil
// and this error has 255 as exit status code, typical for ssh failure for instance), waiting 'delay' after each try, expiring after 'timeout'
func WhileUnsuccessfulWhereRetcode255WithNotify(run func() error, delay time.Duration, timeout time.Duration, notify Notify) fail.Error {
	if delay > timeout {
		logrus.Warnf("unexpected parameters: 'delay' greater than 'timeout' ?? : (%s) > (%s)", delay, timeout)
		delay = timeout / 2
	}

	if notify == nil {
		return fail.InvalidParameterError("notify", "cannot be nil!")
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
	selector := DefaultTimeoutSelector()
	return selector(action{
		Arbiter: arbiter,
		Officer: BackoffSelector()(delay),
		Run:     run,
		Notify:  notify,
		Timeout: timeout,
	})
}

func DefaultNotifier() func(t Try, v verdict.Enum) {
	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics == "" {
		return func(t Try, v verdict.Enum) {
		}
	}

	return func(t Try, v verdict.Enum) {
		switch v {
		case verdict.Retry:
			logrus.Tracef("retrying (#%d), previous error was: %v [%s]", t.Count, t.Err, spew.Sdump(fail.RootCause(t.Err)))
		case verdict.Done:
			if t.Err == nil {
				if t.Count > 1 {
					logrus.Tracef("no more retries, operation was OK")
				}
			} else {
				logrus.Tracef("no more retries, operation had an error %v [%s] but it's considered OK", t.Err, spew.Sdump(fail.RootCause(t.Err)))
			}
		case verdict.Undecided:
			logrus.Tracef("nothing to do")
		case verdict.Abort:
			logrus.Tracef("aborting, previous error was: %v [%s]", t.Err, spew.Sdump(fail.RootCause(t.Err)))
		}
	}
}

func DefaultMetadataNotifier(metaID string) func(t Try, v verdict.Enum) {
	return func(t Try, v verdict.Enum) {
		switch v {
		case verdict.Retry:
			logrus.Tracef("retrying metadata [%s] (#%d), previous error was: %v [%s]", metaID, t.Count, t.Err, spew.Sdump(fail.RootCause(t.Err)))
		case verdict.Done:
			if t.Err == nil {
				if t.Count > 1 {
					logrus.Tracef("no more retries metadata [%s], operation was OK", metaID)
				}
			} else {
				logrus.Tracef("no more retries metadata [%s], operation had an error %v [%s] but it's considered OK", metaID, t.Err, spew.Sdump(fail.RootCause(t.Err)))
			}
		case verdict.Undecided:
			logrus.Tracef("nothing to do, metadata [%s]", metaID)
		case verdict.Abort:
			logrus.Tracef("aborting metadata [%s], previous error was: %v [%s]", metaID, t.Err, spew.Sdump(fail.RootCause(t.Err)))
		}
	}
}

// FIXME: not used...
// DefaultNotifierWithContext ...
func DefaultNotifierWithContext(ctx context.Context) func(t Try, v verdict.Enum) {
	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics == "" {
		return func(t Try, v verdict.Enum) {
		}
	}

	ctxID := ""

	//if ctx != nil && {
	//	if ctx != context.TODO() {
	//		res := ctx.Value(concurrency.KeyForTaskInContext)
	//		if res != nil {
	//			switch rt := res.(type) {
	//			case string:
	//				ctxID = rt
	//			case concurrency.TaskCore:
	//				ctxID, _ = rt.ID()
	//			}
	//		}
	//	}
	//}
	task, xerr := concurrency.TaskFromContext(ctx)
	if xerr == nil {
		ctxID, _ = task.ID()
	}

	if ctxID == "" {
		return func(t Try, v verdict.Enum) {
			switch v {
			case verdict.Retry:
				logrus.Tracef("retrying (#%d), previous error was: %v", t.Count, t.Err)
			case verdict.Done:
				if t.Err == nil {
					logrus.Tracef("no more retries, operation was OK")
				} else {
					logrus.Tracef("no more retries, operation had an error %v but it's considered OK", t.Err)
				}
			case verdict.Undecided:
				logrus.Tracef("nothing to do")
			case verdict.Abort:
				logrus.Tracef("aborting, previous error was: %v", t.Err)
			}
		}
	}

	ctxID = fmt.Sprintf("[%s]", ctxID)
	ctxLog := logrus.WithField(concurrency.KeyForTaskInContext, ctxID)

	return func(t Try, v verdict.Enum) {
		switch v {
		case verdict.Retry:
			ctxLog.Tracef("retrying (#%d), previous error was: %v", t.Count, t.Err)
		case verdict.Done:
			if t.Err == nil {
				if t.Count > 1 {
					ctxLog.Tracef("no more retries, operation was OK")
				}
			} else {
				ctxLog.Tracef("no more retries, operation had an error %v but it's considered OK", t.Err)
			}
		case verdict.Undecided:
			ctxLog.Tracef("nothing to do")
		case verdict.Abort:
			ctxLog.Tracef("aborting, previous error was: %v", t.Err)
		}
	}
}

// WhileSuccessful retries while 'run' is successful (ie 'run' returns an error == nil),
// waiting a duration of 'delay' after each try, expiring after a duration of 'timeout'.
func WhileSuccessful(run func() error, delay time.Duration, timeout time.Duration) fail.Error {
	if delay > timeout {
		logrus.Warnf("unexpected parameters: 'delay' greater than 'timeout' ?? : (%s) > (%s)", delay, timeout)
		delay = timeout / 2
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

	selector := DefaultTimeoutSelector()
	return selector(action{
		Arbiter: arbiter,
		Officer: BackoffSelector()(delay),
		Run:     run,
		Notify:  nil,
		Timeout: timeout,
	})
}

// WhileSuccessfulWithNotify retries while 'run' is successful (ie 'run' returns an error == nil),
// waiting a duration of 'delay' after each try, expiring after a duration of 'timeout'.
// 'notify' is called after each try for feedback.
func WhileSuccessfulWithNotify(run func() error, delay time.Duration, timeout time.Duration, notify Notify) fail.Error {
	if delay > timeout {
		logrus.Warnf("unexpected parameters: 'delay' greater than 'timeout' ?? : (%s) > (%s)", delay, timeout)
		delay = timeout / 2
	}

	if notify == nil {
		return fail.InvalidParameterError("notify", "cannot be nil!")
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
	selector := DefaultTimeoutSelector()
	return selector(action{
		Arbiter: arbiter,
		Officer: BackoffSelector()(delay),
		Run:     run,
		Notify:  notify,
		Timeout: timeout,
	})
}

// loopWithSoftTimeout executes the tries and stops if the elapsed time is gone beyond the timeout (hence the "soft timeout")
func (a action) loopWithSoftTimeout() (ferr fail.Error) {
	arbiter := a.Arbiter
	start := time.Now()

	var duration time.Duration
	count := uint(1)

	defer func() {
		if checkTimeouts := os.Getenv("SAFESCALE_CHECK"); checkTimeouts != "ok" && checkTimeouts != "all" {
			return
		}

		all := false
		if checkTimeouts := os.Getenv("SAFESCALE_CHECK"); checkTimeouts == "all" {
			all = true
		}

		if a.Timeout != 0 {
			if !all {
				if ferr != nil {
					switch ferr.(type) {
					case *fail.ErrAborted:
						return
					}
				}
			}

			duration = time.Since(start)
			if duration > a.Timeout {
				if count <= minNumRetries {
					msg := callstack.DecorateWith("wrong retry-timeout cfg: ", fmt.Sprintf("this timeout (%s) exceeded the mark (%s)", duration, a.Timeout), "", 0)
					logrus.Warnf(msg)
				}
			} else if duration > 55*a.Timeout/100 {
				if count <= minNumRetries {
					if count == 1 {
						msg := callstack.DecorateWith("wrong retry-timeout cfg: ", fmt.Sprintf("this timeout (%s) is too close to the mark (%s)", duration, a.Timeout), "", 0)
						logrus.Warnf(msg)
					} else if ferr != nil {
						msg := callstack.DecorateWith("wrong retry-timeout cfg: ", fmt.Sprintf("this is not retried enough times (only %d)...", count), "", 0)
						logrus.Warnf(msg)
					}

				}
			}
		}
	}()

	if arbiter == nil {
		arbiter = DefaultArbiter
	}

	for ; ; count++ {
		// Perform action
		err := a.Run()

		// Collects the result of the try
		try := Try{
			Start: start,
			Count: count,
			Err:   err,
		}

		// Asks what to do now
		v, retryErr := arbiter(try)

		// Notify to interested parties
		if a.Notify != nil {
			a.Notify(try, v)
		}

		switch v {
		case verdict.Done:
			// Returns the error if no retry is wanted
			return retryErr
		case verdict.Abort:
			// Abort wanted, returns an error explaining why
			return retryErr
		default:
			// Retry is wanted, so blocks the loop the amount of time needed
			if a.Officer != nil {
				a.Officer.Block(try)
			}
		}
	}
}

// loopWithHardTimeout executes the tries and stops at the exact timeout (hence the "hard timeout")
func (a action) loopWithHardTimeout() (ferr fail.Error) {
	timeout := a.Timeout
	if timeout == 0 {
		timeout = temporal.GetOperationTimeout()
	}

	var (
		arbiter = a.Arbiter
		start   = time.Now()
	)
	if arbiter == nil {
		arbiter = DefaultArbiter
	}

	var duration time.Duration
	count := uint(1)

	defer func() {
		if checkTimeouts := os.Getenv("SAFESCALE_CHECK"); checkTimeouts != "ok" && checkTimeouts != "all" {
			return
		}

		all := false
		if checkTimeouts := os.Getenv("SAFESCALE_CHECK"); checkTimeouts == "all" {
			all = true
		}

		if a.Timeout != 0 {
			if !all {
				if ferr != nil {
					switch ferr.(type) {
					case *fail.ErrAborted:
						return
					}
				}
			}

			duration = time.Since(start)
			if duration > a.Timeout {
				if count <= minNumRetries {
					msg := callstack.DecorateWith("wrong retry-timeout cfg: ", fmt.Sprintf("this timeout (%s) exceeded the mark (%s)", duration, a.Timeout), "", 0)
					logrus.Warnf(msg)
				}
			} else if duration > 55*a.Timeout/100 {
				if count <= minNumRetries {
					if count == 1 {
						msg := callstack.DecorateWith("wrong retry-timeout cfg: ", fmt.Sprintf("this timeout (%s) is too close to the mark (%s)", duration, a.Timeout), "", 0)
						logrus.Warnf(msg)
					} else if ferr != nil {
						msg := callstack.DecorateWith("wrong retry-timeout cfg: ", fmt.Sprintf("this is not retried enough times (only %d)...", count), "", 0)
						logrus.Warnf(msg)
					}

				}
			}
		}
	}()

	// the time.After inside the for loop (16 lines below), is evaluated each time we enter the loop, if we want a timeout for
	// the whole loop, we need to define it outside the loop, this is the 'desist' timeout
	// ideally, the timeout inside the loop and the timeout outside should be different, something like: outsideTimeout = #maxAllowedIterations * insideTimeout
	desist := time.After(timeout)
	for ; ; count++ {
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
			err = fail.TimeoutError(nil, timeout, "operation timeout")
		case <-desist:
			err = fail.TimeoutError(nil, timeout, "desist timeout")
		}

		// Collects the result of the try
		try := Try{
			Start: start,
			Count: count,
			Err:   err,
		}

		// Asks what to do now
		v, retryErr := arbiter(try)
		if a.Notify != nil {
			a.Notify(try, v)
		}

		switch v {
		case verdict.Done:
			// Returns the error if no retry is wanted
			return retryErr
		case verdict.Abort:
			// Abort wanted, returns an error explaining why
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
					err = fail.TimeoutError(nil, timeout, "desist timeout")
					_ = err
				}
			}
		}
	}
}

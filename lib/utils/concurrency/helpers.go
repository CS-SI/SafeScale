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

package concurrency

import (
	"fmt"
	"math"
	mrand "math/rand"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"golang.org/x/exp/rand"
)

// waitTimeout waits for the WaitGroup for the specified max timeout.
// Returns true if waiting timed out.
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

// randomInt will return a random integer between a specified range.
func randomInt(min, max int) int {
	if min == max {
		return min
	}
	// mrand.Seed(time.Now().UnixNano())
	return mrand.Intn(max-min) + min
}

// randomIntWithReseed restarts pseudorandom seed then returns a random integer between a specified range.
func randomIntWithReseed(min, max int) int {
	if min == max {
		return min
	}
	mrand.Seed(time.Now().UnixNano())
	return mrand.Intn(max-min) + min
}

func validTest(st int, latency int) bool {
	iterations := int64(math.Ceil(float64(float64(st) / float64(latency))))
	tempo := time.Duration(latency) * time.Millisecond
	count := int64(0)
	begin := time.Now()

	for { // do some work, then look for aborted, again and again
		if count >= iterations {
			break
		}
		// some work
		time.Sleep(tempo) // that is actually the latency between abortion and its check t.Aborted() in the line below
		count++
	}

	elapsed := time.Since(begin)
	return elapsed <= time.Duration(st+latency)*time.Millisecond
}

func taskgenWithCustomFunc(low int, high int, latency int, cleanfactor int, probError float32, probPanic float32, actionHandlesPanicByItself bool, custom func(chan string) error) TaskAction {
	return func(t Task, parameters TaskParameters) (_ TaskResult, xerr fail.Error) {
		traceR := newTracer(t, false) // change to true to display traces

		type internalRes struct {
			ir  interface{}
			err error
		}

		if actionHandlesPanicByItself {
			defer fail.OnPanic(&xerr)
		}

		ctx := t.Context()

		weWereAborted := false
		rd := randomInt(low, high)

		resch := make(chan internalRes)
		go func() {
			iterations := int64(math.Ceil(float64(float64(rd) / float64(latency))))
			tempo := time.Duration(math.Min(float64(latency), float64(rd))) * time.Millisecond
			count := int64(0)
			begin := time.Now()
			defer func() {
				traceR.trace("low=%d, high=%d, tempo=%v, iterations=%d, took %v", low, high, tempo, iterations, time.Since(begin))
			}()

			wrongTest := false
			realTime := time.Now()
			for { // do some work, then look for aborted, again and again
				if count >= iterations {
					break
				}
				// some work
				time.Sleep(tempo) // that is actually the latency between abortion and its check t.Aborted() in the line below
				count++
				if t.Aborted() {
					// if so, we shouldn't be still running, sleep adds too much overhead
					if time.Since(realTime) > time.Duration(rd+latency)*time.Millisecond {
						wrongTest = true
					}
					traceR.trace("aborted after %d iterations (max allowed=%d)", count, iterations)
					// Cleaning up first before leaving... ;)
					if cleanfactor > 0 {
						time.Sleep(time.Duration(randomInt(cleanfactor*low, cleanfactor*high)) * time.Millisecond)
					}
					weWereAborted = true
					if custom != nil {
						_ = custom(parameters.(chan string)) // for side-effects
					}
					break
				}
			}

			// simulation of error conditions, starting by panic
			coinFlip := rand.Float32() < probPanic
			if coinFlip {
				panic("it hurts")
			}

			if weWereAborted {
				if wrongTest {
					resch <- internalRes{
						ir:  "",
						err: fail.AbortedError(nil, "inconsistent"),
					}
					return
				}
				resch <- internalRes{
					ir:  "we were killed",
					err: fail.AbortedError(nil, "we were killed"),
				}
				return
			}

			if custom != nil {
				_ = custom(parameters.(chan string)) // for side-effects
			}

			coinFlip = rand.Float32() < probError
			var iErr error = nil
			if coinFlip {
				iErr = fmt.Errorf("it was head")
			}

			resch <- internalRes{
				ir:  "Ahhhh",
				err: fail.ConvertError(iErr),
			}
			return
		}()

		select {
		case res := <-resch:
			return res.ir, fail.ConvertError(res.err)
		case <-time.After(time.Duration(rd-1) * time.Millisecond):
			return "Ahhhh", nil
		case <-ctx.Done():
			return "we were killed", fail.AbortedError(nil, "we were killed")
		}
	}
}

func taskgen(low int, high int, latency int, cleanfactor int, probError float32, probPanic float32, actionHandlesPanicByItself bool) TaskAction {
	return taskgenWithCustomFunc(low, high, latency, cleanfactor, probError, probPanic, actionHandlesPanicByItself, nil)
}

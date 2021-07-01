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

func taskgen(low int, high int, latency int, cleanfactor int, probError float32, probPanic float32, actionHandlesPanicByItself bool) TaskAction {
	return func(t Task, parameters TaskParameters) (_ TaskResult, xerr fail.Error) {
		traceR := newTracer(t, true)   // change to true to display traces

		weWereAborted := false
		iterations := int64(high / latency)
		workTime := time.Duration(randomInt(low, high)) * time.Millisecond
		tempo := workTime / time.Duration(iterations)
		begin := time.Now()
		defer func() {
			traceR.trace("low=%d, high=%d, workTime=%v, tempo=%v, iterations=%d, took %v", low, high, workTime, tempo, iterations, time.Since(begin))
		}()

		if actionHandlesPanicByItself {
			defer fail.OnPanic(&xerr)
		}
		weWereAborted := false
		iterations := int64(high / latency)
		rn := randomInt(low, high)
		tempo := time.Duration(int64(math.Ceil(float64(rn)/float64(iterations)))) * time.Millisecond
		count := int64(0)
		// fmt.Printf("Sleeping %d iterations and a time of %s\n", iterations, tempo)
		for { // do some work, then look for aborted, again and again
			if count == iterations {
				break
			}
			// some work
			time.Sleep(tempo) // that is actually the latency between abortion and its check t.Aborted() in the line below
			count++
			if t.Aborted() {
				traceR.trace("aborted after %d iterations (max allowed=%d)", count, iterations)
				// Cleaning up first before leaving... ;)
				if cleanfactor > 0 {
					time.Sleep(time.Duration(randomInt(cleanfactor*low, cleanfactor*high)) * time.Millisecond)
				}
				weWereAborted = true
				break
			}
		}

		// simulation of error conditions, starting by panic
		coinFlip := rand.Float32() < probPanic
		if coinFlip {
			panic("it hurts")
		}

		if weWereAborted {
			return "", fail.AbortedError(nil, "we were killed") // better to return a 'zero' value as the 1st return value
		}

		coinFlip = rand.Float32() < probError
		var iErr error = nil
		if coinFlip {
			iErr = fmt.Errorf("it was head")
		}

		return "Ahhhh", fail.ConvertError(iErr)
	}
}

func taskgenWithCustomFunc(low int, high int, latency int, cleanfactor int, probError float32, probPanic float32, actionHandlesPanicByItself bool, custom func() error) TaskAction {
	return func(t Task, parameters TaskParameters) (_ TaskResult, xerr fail.Error) {
		if actionHandlesPanicByItself {
			defer fail.OnPanic(&xerr)
		}
		iterations := int64(high / latency)
		rn := randomInt(low, high)
		tempo := time.Duration(int64(math.Ceil(float64(rn)/float64(iterations)))) * time.Millisecond
		count := int64(0)
		var iErr error = nil

		weWereAborted := false
		for { // do some work, then look for aborted, again and again
			if count > iterations {
				break
			}
			// some work
			time.Sleep(tempo) // that is actually the latency between abortion and its check t.Aborted() in the line below
			if t.Aborted() {
				// Cleaning up first before leaving... ;)
				if cleanfactor > 0 {
					time.Sleep(time.Duration(randomInt(cleanfactor*low, cleanfactor*high)) * time.Millisecond)
				}
				weWereAborted = true
				if custom != nil {
					_ = custom() // for side-effects
				}
				break
			}
			count++
		}

		if custom != nil {
			_ = custom() // for side-effects
		}
		// simulation of error conditions, starting by panic
		coinFlip := rand.Float32() < probPanic
		if coinFlip {
			panic("it hurts")
		}

		if weWereAborted {
			return "", fail.AbortedError(nil, "we were killed")
		}

		coinFlip = rand.Float32() < probError
		if coinFlip {
			iErr = fmt.Errorf("it was head")
		}

		return "Ahhhh", fail.ConvertError(iErr)
	}
}

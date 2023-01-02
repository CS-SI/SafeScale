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
	"math"
	mrand "math/rand"
	"time"
)

// Officer sleeps or selects any amount of time for each try
type Officer struct {
	Block func(Try)

	variables interface{}
}

// Backoff is the type that must implement algorithms that space out retries to avoid congestion
type Backoff func(duration time.Duration) *Officer

// Constant sleeps for duration duration
func Constant(duration time.Duration) *Officer {
	jitter := getJitter(duration)

	o := Officer{
		Block: func(t Try) {
			toSleep := duration + jitter
			if toSleep < 0 {
				toSleep = duration
			}
			time.Sleep(toSleep)
		},
	}
	return &o
}

// Incremental sleeps for duration + the number of tries
func Incremental(duration time.Duration) *Officer {
	jitter := getJitter(duration)

	o := Officer{
		Block: func(t Try) {
			toSleep := duration + time.Duration(t.Count) + jitter
			if toSleep < 0 {
				toSleep = duration + time.Duration(t.Count)
			}

			time.Sleep(toSleep)
		},
	}
	return &o

}

// Linear sleeps for duration * the number of tries
func Linear(duration time.Duration) *Officer {
	jitter := getJitter(duration)

	o := Officer{
		Block: func(t Try) {
			toSleep := duration*time.Duration(t.Count) + jitter
			if toSleep < 0 {
				toSleep = duration * time.Duration(t.Count)
			}
			time.Sleep(toSleep)
		},
	}
	return &o
}

// Exponential sleeps for duration base * 2^tries
func Exponential(base time.Duration) *Officer {
	jitter := getJitter(base)

	o := Officer{
		Block: func(t Try) {
			toSleep := time.Duration(float64(base)*math.Exp(float64(t.Count))) + jitter
			if toSleep < 0 {
				toSleep = time.Duration(float64(base) * math.Exp(float64(t.Count)))
			}
			time.Sleep(toSleep)
		},
	}
	return &o
}

// getJitter is a utility function to help Backoff functions not hammering the network in a predictable way
func getJitter(base time.Duration) time.Duration {
	var jitter time.Duration
	if base >= 1*time.Second {
		jitter = time.Duration(randomInt(-100, 100)) * time.Millisecond
	} else {
		jitter = time.Duration(randomInt(int(-base.Milliseconds()*10/100), int(base.Milliseconds()*10/100))) * time.Millisecond
	}
	return jitter
}

// Fibonacci sleeps for duration * fib(tries)
func Fibonacci(base time.Duration) *Officer {
	o := Officer{
		variables: map[string]uint64{
			"pre": 0,
			"cur": 1,
		},
	}

	jitter := getJitter(base)

	o.Block = func(t Try) {
		p, _ := o.variables.(map[string]uint64) // nolint
		var pre, cur uint64
		pre = p["pre"]
		cur, p["pre"] = p["cur"], p["cur"]
		cur += pre
		p["cur"] = cur

		toSleep := base*time.Duration(cur) + jitter
		if toSleep < 0 {
			toSleep = base * time.Duration(cur)
		}

		time.Sleep(toSleep)
	}

	return &o
}

func randomInt(min, max int) int {
	if min == max {
		return min
	}
	mrand.Seed(time.Now().Unix())
	if min > max {
		return mrand.Intn(min-max) + max // nolint
	}

	return mrand.Intn(max-min) + min // nolint
}

func Randomized(bottom time.Duration, top time.Duration) *Officer {
	o := Officer{
		Block: func(t Try) {
			sleepTime := time.Duration(randomInt(int(bottom.Milliseconds()), int(top.Milliseconds()))) * time.Millisecond
			time.Sleep(sleepTime)
		},
	}
	return &o
}

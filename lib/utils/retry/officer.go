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

type Backoff func(duration time.Duration) *Officer

// Constant sleeps for duration duration
func Constant(duration time.Duration) *Officer {
	o := Officer{
		Block: func(t Try) {
			time.Sleep(duration)
		},
	}
	return &o
}

// Incremental sleeps for duration + the number of tries
func Incremental(duration time.Duration) *Officer {
	o := Officer{
		Block: func(t Try) {
			time.Sleep(duration + time.Duration(t.Count))
		},
	}
	return &o

}

// Linear sleeps for duration * the number of tries
func Linear(duration time.Duration) *Officer {
	o := Officer{
		Block: func(t Try) {
			time.Sleep(duration * time.Duration(t.Count))
		},
	}
	return &o
}

// Exponential sleeps for duration base * 2^tries
func Exponential(base time.Duration) *Officer {
	o := Officer{
		Block: func(t Try) {
			time.Sleep(time.Duration(float64(base) * math.Exp(float64(t.Count))))
		},
	}
	return &o
}

// Fibonacci sleeps for duration * fib(tries)
func Fibonacci(base time.Duration) *Officer {
	o := Officer{
		variables: map[string]uint64{
			"pre": 0,
			"cur": 1,
		},
	}
	o.Block = func(t Try) {
		p := o.variables.(map[string]uint64)
		var pre, cur uint64
		pre = p["pre"]
		cur, p["pre"] = p["cur"], p["cur"]
		cur += pre
		p["cur"] = cur

		time.Sleep(base * time.Duration(cur))
	}

	return &o
}

func randomInt(min, max int) int {
	mrand.Seed(time.Now().Unix())
	return mrand.Intn(max-min) + min
}

func Randomized(bottom time.Duration, top time.Duration) *Officer { // FIXME: Use this
	o := Officer{
		Block: func(t Try) {
			sleepTime := time.Duration(randomInt(int(bottom.Milliseconds()), int(top.Milliseconds()))) * time.Millisecond
			time.Sleep(sleepTime)
		},
	}
	return &o
}

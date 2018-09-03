/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"time"

	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/retry/Verdict"
)

// Arbiter sleeps or selects any amount of time for each attempt.
type Arbiter func(Try) (Verdict.Enum, error)

// DefaultArbiter allows 10 retries, with a maximum duration of 30 seconds
var DefaultArbiter = PrevailDone(Max(10), Timeout(30*time.Second))

// PrevailRetry aggregates verdicts from Arbiters for a try :
// - Returns Abort and the error as soon as an arbiter decides for an Abort.
// - If at least one arbiter returns Retry without any Abort from others, returns Retry with nil error.
// - Otherwise returns Done with nil error.
func PrevailRetry(arbiters ...Arbiter) Arbiter {
	return func(t Try) (Verdict.Enum, error) {
		final := Verdict.Done
		for _, a := range arbiters {
			verdict, err := a(t)

			switch verdict {
			case Verdict.Retry:
				final = Verdict.Retry
			case Verdict.Abort:
				return Verdict.Abort, err
			}
		}
		return final, nil
	}
}

// PrevailDone aggregates verdicts from Arbiters for a try :
// - Returns Abort and the error as soon as an Abort is decided.
// - If at least one arbiter return Done without any Abort, returns Done with nil error.
// - Otherwise returns Retry with nil error.
func PrevailDone(arbiters ...Arbiter) Arbiter {
	return func(t Try) (Verdict.Enum, error) {
		final := Verdict.Retry
		for _, a := range arbiters {
			verdict, err := a(t)

			switch verdict {
			case Verdict.Done:
				final = Verdict.Done
			case Verdict.Abort:
				return Verdict.Abort, err
			}
		}
		return final, nil
	}

}

// Unsuccessful returns Retry when the try produced an error.
func Unsuccessful() Arbiter {
	return func(t Try) (Verdict.Enum, error) {
		if t.Err != nil {
			return Verdict.Retry, nil
		}
		return Verdict.Done, nil
	}
}

// Unsuccessful255 returns Retry when the try produced an error with code 255,
// all other code are considered as sucessful and returns Done.
func Unsuccessful255() Arbiter {
	return func(t Try) (Verdict.Enum, error) {
		if t.Err != nil {
			_, retCode, _ := utils.ExtractRetCode(t.Err)
			if retCode == 255 {
				return Verdict.Retry, nil
			}
		}
		return Verdict.Done, nil
	}
}

// Successful returns Retry when the try produced no error.
func Successful() Arbiter {
	return func(t Try) (Verdict.Enum, error) {
		if t.Err == nil {
			return Verdict.Retry, nil
		}
		return Verdict.Done, nil
	}
}

// Timeout returns Abort after a duration of time passes since the first try.
func Timeout(limit time.Duration) Arbiter {
	return func(t Try) (Verdict.Enum, error) {
		if t.Err != nil {
			if time.Since(t.Start) >= limit {
				return Verdict.Abort, TimeoutError{limit: limit}
			}
			return Verdict.Retry, nil
		}
		return Verdict.Done, nil
	}
}

// Max errors after a limited number of tries
func Max(limit uint) Arbiter {
	return func(t Try) (Verdict.Enum, error) {
		if t.Err != nil {
			if t.Count >= limit {
				return Verdict.Abort, MaxError{limit: limit}
			}
			return Verdict.Retry, nil
		}
		return Verdict.Done, nil
	}
}

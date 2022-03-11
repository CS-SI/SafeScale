/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/v21/lib/utils/temporal"
)

// Arbiter sleeps or selects any amount of time for each attempt.
type Arbiter func(Try) (verdict.Enum, fail.Error)

// DefaultArbiter allows 10 retries, with a maximum duration of 30 seconds
var DefaultArbiter = PrevailDone(Max(10), Timeout(temporal.BigDelay()))

// CommonArbiter allows between 5 and 10 retries
var CommonArbiter = PrevailDone(Min(5), Max(10))

// ArbiterAggregator this type helps easy replacement of PrevailDone
type ArbiterAggregator func(arbiters ...Arbiter) Arbiter

// PrevailRetry aggregates verdicts from Arbiters for a try:
// - Returns Abort and the error as soon as an arbiter decides for an Abort.
// - If at least one arbiter returns Retry without any Abort from others, returns Retry with nil error.
// - Otherwise returns Done with nil error.
func PrevailRetry(arbiters ...Arbiter) Arbiter {
	return func(t Try) (verdict.Enum, fail.Error) {
		final := verdict.Done
		for _, a := range arbiters {
			v, err := a(t)

			switch v {
			case verdict.Retry:
				final = verdict.Retry
			case verdict.Abort:
				return verdict.Abort, err
			case verdict.Undecided:
				continue
			}
		}
		return final, nil
	}
}

// PrevailDone aggregates verdicts from Arbiters for a try:
// - Returns Abort and the error as soon as an Abort is decided.
// - If at least one arbiter return Done without any Abort, returns Done with nil error.
// - Otherwise returns Retry with nil error.
func PrevailDone(arbiters ...Arbiter) Arbiter {
	return func(t Try) (verdict.Enum, fail.Error) {
		final := verdict.Retry
		for _, a := range arbiters {
			v, err := a(t)

			switch v {
			case verdict.Done:
				final = verdict.Done
			case verdict.Abort:
				return verdict.Abort, err
			case verdict.Undecided:
				continue
			}
		}
		return final, nil
	}
}

// Unsuccessful returns Retry when the try produced an error; returns Done otherwise
func Unsuccessful() Arbiter {
	return func(t Try) (verdict.Enum, fail.Error) {
		if t.Err != nil {
			switch cerr := t.Err.(type) {
			case *ErrStopRetry:
				return verdict.Abort, cerr
			case *fail.ErrRuntimePanic:
				return verdict.Abort, cerr
			default:
				return verdict.Retry, fail.ConvertError(t.Err)
			}
		}
		return verdict.Done, nil
	}
}

func OrArbiter(arbiters ...Arbiter) Arbiter {
	return func(t Try) (verdict.Enum, fail.Error) {
		final := verdict.Retry
		var lastErr fail.Error

		for _, a := range arbiters {
			v, err := a(t)

			switch v {
			case verdict.Done:
				return verdict.Done, nil
			case verdict.Abort:
				final = verdict.Abort
				lastErr = err
			case verdict.Undecided:
				continue
			}
		}
		return final, lastErr
	}
}

// Successful returns Retry when the try produced no error; returns Done otherwise
func Successful() Arbiter {
	return func(t Try) (verdict.Enum, fail.Error) {
		if t.Err != nil {
			return verdict.Done, fail.ConvertError(t.Err)
		}
		return verdict.Retry, nil
	}
}

// Timeout returns Abort after a duration of time passes since the first try, while the try returns an error; returns Done if no error occurred during the last try
func Timeout(limit time.Duration) Arbiter {
	return func(t Try) (verdict.Enum, fail.Error) {
		if t.Err != nil {
			switch cerr := t.Err.(type) {
			case *ErrStopRetry:
				return verdict.Abort, cerr
			case *fail.ErrRuntimePanic:
				return verdict.Abort, cerr
			default:
				if time.Since(t.Start) >= limit {
					return verdict.Abort, TimeoutError(t.Err, limit, time.Since(t.Start))
				}

				return verdict.Undecided, fail.ConvertError(t.Err)
			}
		}

		if time.Since(t.Start) >= limit {
			return verdict.Abort, TimeoutError(t.Err, limit, time.Since(t.Start))
		}

		return verdict.Undecided, nil
	}
}

// Max errors after a limited number of tries, while the last try returned an error
func Max(limit uint) Arbiter {
	if limit == 0 {
		panic("invalid Max configuration")
	}
	return func(t Try) (verdict.Enum, fail.Error) {
		if t.Err != nil {
			switch cerr := t.Err.(type) {
			case *ErrStopRetry:
				return verdict.Abort, cerr
			case *fail.ErrRuntimePanic:
				return verdict.Abort, cerr
			default:
				if t.Count > limit { // last try is also good
					return verdict.Abort, LimitError(t.Err, limit)
				}

				return verdict.Retry, fail.ConvertError(t.Err)
			}
		}
		return verdict.Undecided, nil
	}
}

// Min errors after a limited number of tries, while the last try returned an error
func Min(limit uint) Arbiter {
	if limit == 0 {
		panic("invalid Min configuration")
	}
	return func(t Try) (verdict.Enum, fail.Error) {
		if t.Err != nil {
			switch cerr := t.Err.(type) {
			case *ErrStopRetry:
				return verdict.Abort, cerr
			case *fail.ErrRuntimePanic:
				return verdict.Abort, cerr
			default:
				if t.Count < limit { // last try is also good
					return verdict.Retry, fail.ConvertError(t.Err)
				}

				return verdict.Undecided, fail.ConvertError(t.Err)
			}
		}
		return verdict.Undecided, nil
	}
}

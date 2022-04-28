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
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v21/lib/utils/temporal"
)

// ErrTimeout is used when a timeout occurs.
type ErrTimeout = fail.ErrTimeout

// TimeoutError creates an error of type ErrTimeout
func TimeoutError(err error, limit time.Duration, actual time.Duration, options ...data.ImmutableKeyValue) fail.Error {
	var (
		msg      string
		decorate bool
	)

	if len(options) > 0 {
		for _, v := range options {
			switch v.Key() { // nolint
			case "callstack":
				// no panics if value is not a bool
				decorate, _ = v.Value().(bool) // nolint
			}
		}
	}

	msg = fmt.Sprintf("retries timed out after %s (timeout defined at %s)", temporal.FormatDuration(actual), temporal.FormatDuration(limit))
	if decorate {
		msg = callstack.DecorateWith(msg, "", "", 0)
	}
	return fail.TimeoutError(err, limit, msg)
}

// ErrLimit is used when a limit is reached.
type ErrLimit = fail.ErrOverflow

// LimitError creates an error of type ErrLimit.
func LimitError(err error, limit uint) fail.Error {
	return fail.OverflowError(err, limit, "retry limit exceeded")
}

// ErrStopRetry is returned when the context needs to stop the retries
type ErrStopRetry = fail.ErrAborted

// StopRetryError creates an error of type ErrStopRetry
func StopRetryError(err error, msg ...interface{}) fail.Error {
	newMessage := strprocess.FormatStrings(msg...)
	if newMessage == "" {
		newMessage = "stopping retries"
	} else {
		newMessage = fmt.Sprintf("stopping retries: %s", newMessage)
	}
	switch ce := err.(type) {
	case *fail.ErrAborted: // do not embed abort inside an abort
		ce.Annotate("message", newMessage)
		return ce
	default:
		return fail.AbortedError(err, newMessage)
	}
}

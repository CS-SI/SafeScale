/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package net

import (
	"net"
	"net/url"
	"reflect"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
)

// WhileCommunicationUnsuccessful executes callback inside a retry loop with tolerance for communication errors (relative to net package),
// asking "waitor" to wait between each try, with a duration limit of 'timeout'.
func WhileCommunicationUnsuccessful(callback func() error, waitor *retry.Officer, timeout time.Duration) fail.Error {
	if waitor == nil {
		return fail.InvalidParameterError("waitor", "cannot be nil")
	}

	// xerr := retry.WhileUnsuccessful(
	// 	func() error {
	// 		return normalizeError(callback())
	// 	},
	//  delay,
	// 	timeout,
	// )

	var arbiter retry.Arbiter
	if timeout <= 0 {
		arbiter = retry.Unsuccessful()
	} else {
		arbiter = retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(timeout))
	}

	xerr := retry.Action(
		func() error {
			return normalizeError(callback())
		},
		arbiter,
		waitor,
		nil,
		nil,
		func(t retry.Try, v verdict.Enum) {
			// if v != verdict.Done {
			// 	spew.Dump(v)
			// }
			switch v {
			case verdict.Retry:
				logrus.Warningf("communication failed (%s), retrying", t.Err.Error())
			}
		},
	)
	if xerr != nil {
		switch realErr := xerr.(type) {
		case *retry.ErrStopRetry:
			xerr = fail.ToError(realErr.Cause())
		case *retry.ErrTimeout:
			xerr = fail.ToError(realErr.Cause())
		}
		return xerr
	}
	return nil
}

// WhileCommunicationUnsuccessfulDelay1Second executes callback inside a retry loop with tolerance for communication errors (relative to net package),
// waiting 1 second between each try, with a limit of 'timeout'
func WhileCommunicationUnsuccessfulDelay1Second(callback func() error, timeout time.Duration) fail.Error {
	return WhileCommunicationUnsuccessful(callback, retry.Constant(1*time.Second), timeout)
}

// normalizeError analyzes the error passed as parameter and rewrite it to be more explicit
// If the error is not a communication error, do not let a chance to retry by returning a *retry.ErrAborted error
// containing the causing error in it
func normalizeError(in error) (err error) {
	// VPL: see if we could replace this defer with retry notification ability in retryOnCommunicationFailure
	defer func() {
		if err != nil {
			switch err.(type) {
			case fail.ErrInvalidRequest:
				logrus.Warning(err.Error())
			case *fail.ErrInvalidRequest:
				logrus.Warning(err.Error())
			}
		}
	}()

	if in != nil {
		switch realErr := in.(type) {
		case *url.Error:
			return normalizeURLError(realErr)
		case fail.Error: // a fail.Error may contain a cause of type *url.Error; it's the way used to propagate an *url.Error received by drivers.
			// In this case, normalize this url.Error accordingly
			switch cause := realErr.Cause().(type) {
			case *url.Error:
				return normalizeURLError(cause)
			}
			return retry.StopRetryError(in)
		default:
			// In any other case, the error should explain the potential retry has to stop
			return retry.StopRetryError(in)
		}
	}
	return nil
}

func normalizeURLError(err *url.Error) fail.Error {
	switch commErr := err.Err.(type) {
	case *net.DNSError:
		return fail.InvalidRequestError("failed to resolve by DNS: %v", commErr)
	default:
		return fail.InvalidRequestError("failed to communicate (error type: %s): %v", reflect.TypeOf(commErr).String(), commErr)
	}
}

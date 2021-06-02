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

package stacks

import (
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// RetryableRemoteCall calls a remote API with communication failure tolerance
// Remote API is done inside 'callback' parameter and returns remote error if necessary that 'convertError' function convert to SafeScale error
func RetryableRemoteCall(callback func() error, convertError func(error) fail.Error) fail.Error {
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	var normalizeError func(err error) fail.Error
	if convertError != nil {
		normalizeError = func(err error) fail.Error { return convertError(err) }
	} else {
		normalizeError = fail.ConvertError
	}

	// Execute the remote call with tolerance for transient communication failure
	xerr := netutils.WhileUnsuccessfulButRetryable(
		func() error {
			if innerErr := callback(); innerErr != nil {
				captured := normalizeError(innerErr)
				// Do not retry if not found, duplicate or invalid request errors
				switch captured.(type) {
				case *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest:
					return retry.StopRetryError(captured)
				default:
				}
				return captured
			}
			return nil
		},
		retry.Fibonacci(1*time.Second), // waiting time between retries follows Fibonacci numbers x 1s
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			if xerr.Cause() != nil {
				return fail.ConvertError(xerr.Cause())
			}
			return fail.ConvertError(xerr)
		case *retry.ErrTimeout: // On timeout, raise a NotFound error with the cause as message
			if xerr.Cause() != nil {
				return fail.NotFoundError(xerr.Cause().Error())
			}
			return fail.NotFoundError(xerr.Error())
		default:
			return xerr
		}
	}
	return nil
}

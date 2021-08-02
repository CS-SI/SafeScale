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
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// RetryableRemoteCall calls a remote API with tolerance to communication failures
// Remote API is done inside 'callback' parameter and returns remote error if necessary that 'convertError' function convert to SafeScale error
func RetryableRemoteCall(callback func() error, convertError func(error) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

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
	xerr = netutils.WhileUnsuccessfulButRetryable(
		func() (nested error) {
			defer fail.OnPanic(&nested)
			if innerErr := callback(); innerErr != nil {
				captured := normalizeError(innerErr)
				switch captured.(type) { // nolint
				case *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
					return retry.StopRetryError(captured)
				default:
					return captured
				}
			}
			return nil
		},
		retry.Fibonacci(temporal.GetMinDelay()), // waiting time between retries follows Fibonacci numbers x 1s
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.ConvertError(fail.Cause(xerr))
		case *retry.ErrTimeout: // On timeout, raise a NotFound error with the cause as message
			return fail.NotFoundError(fail.Cause(xerr).Error())
		default:
			return xerr
		}
	}
	return nil
}

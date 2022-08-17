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

package stacks

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// RetryableRemoteCall calls a remote API with tolerance to communication failures
// Remote API is done inside 'callback' parameter and returns remote error if necessary that 'convertError' function convert to SafeScale error
func RetryableRemoteCall(ctx context.Context, callback func() error, convertError func(error) fail.Error, options ...retry.Option) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	var normalizeError func(err error) fail.Error
	if convertError != nil {
		normalizeError = func(err error) fail.Error { return convertError(err) }
	} else {
		normalizeError = fail.ConvertError
	}

	plannedAction := retry.NewAction(
		retry.Fibonacci(temporal.MinDelay()), // waiting time between retries follows Fibonacci numbers x MinDelay()
		nil,
		func() (nested error) {
			defer fail.OnPanic(&nested)
			if innerErr := callback(); innerErr != nil {
				captured := normalizeError(innerErr)
				switch captured.(type) { // nolint
				case *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
					return retry.StopRetryError(captured)
				case *fail.ErrOverload:
					return retry.StopRetryError(captured)
				default:
					return captured
				}
			}
			return nil
		},
		nil,
		temporal.CommunicationTimeout(),
	)

	for _, opt := range options { // now we can override the actions without changing every function that invokes RetryableRemoteCall, only callers interested in such thing will add options parameters in their invocation
		err := opt(plannedAction)
		if err != nil {
			return fail.ConvertError(err)
		}
	}

	// Execute the remote call with tolerance for transient communication failure
	xerr := netutils.WhileUnsuccessfulButRetryable(
		plannedAction.Run,
		plannedAction.Officer,
		plannedAction.Timeout,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout: // On timeout, we keep the last error as cause
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}
	return nil
}

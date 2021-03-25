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
	// xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
	xerr := netutils.WhileUnsuccessfulButRetryable(
		func() error {
			if innerErr := callback(); innerErr != nil {
				innerErr = normalizeError(innerErr)
				switch innerErr.(type) { //nolint
				case *fail.ErrNotFound:
					return retry.StopRetryError(innerErr)
				}
				return innerErr
			}
			return nil
		},
		retry.Fibonacci(1*time.Second), // waiting time between retries follows Fibonacci numbers x 1s
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.ConvertError(xerr.Cause())
		case *retry.ErrTimeout: // On timeout, raise a NotFound error with the cause as message
			return fail.NotFoundError(xerr.Cause().Error())
		default:
			return xerr
		}
	}
	return nil
}

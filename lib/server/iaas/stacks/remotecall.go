package stacks

import (
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// RetryableRemoteCall calls a remote API with communication failure tolerance
// Remote API is done inside 'callback' parameter and returns remote error if necessary that 'convertError' function convert to SafeScale error
func RetryableRemoteCall(callback func() error, convertError func(error) fail.Error) fail.Error {
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	var normalizeError func(err error) fail.Error
	if convertError != nil {
		normalizeError = func(err error) fail.Error { return convertError(err) }
	} else {
		normalizeError = func(err error) fail.Error { return fail.ToError(err) }
	}

	// Execute the remote call with tolerance for transient communication failure
	xerr := netutils.WhileCommunicationUnsuccessfulDelay1Second(
		func() error {
			if innerErr := callback(); innerErr != nil {
				innerErr = normalizeError(innerErr)
				switch innerErr.(type) {
				case *fail.ErrNotFound:
					return retry.StopRetryError(innerErr)
				}
				return innerErr
			}
			return nil
		},
		temporal.GetCommunicationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // On StopRetry, the real error is the cause
			return fail.ToError(xerr.Cause())
		case *retry.ErrTimeout: // On Timeout, raise a NotFound error with the cause as message
			return fail.NotFoundError(xerr.Cause().Error())
		default:
			return xerr
		}
	}
	return nil
}

package retry

import (
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// ErrTimeout is used when a timeout occurs.
type ErrTimeout = fail.ErrTimeout

// TimeoutError ...
func TimeoutError(err error, limit time.Duration) *ErrTimeout {
	// msg := fmt.Sprintf("retries timed out after %s", temporal.FormatDuration(limit))
	msg := callstack.DecorateWith(fmt.Sprintf("retries timed out after %s", temporal.FormatDuration(limit)), "", "", 0)
	return fail.TimeoutError(err, limit, msg)
}

// ErrLimit is used when a limit is reached.
type ErrLimit = fail.ErrOverflow

// LimitError ...
func LimitError(err error, limit uint) *ErrLimit {
	return fail.OverflowError(err, limit, "retry limit exceeded")
}

// ErrStopRetry is returned when the context needs to stop the retries
type ErrStopRetry = fail.ErrAborted

// StopRetryError ...
func StopRetryError(err error, msg ...interface{}) *ErrStopRetry {
	newMessage := strprocess.FormatStrings(msg...)
	if newMessage == "" {
		newMessage = "stopping retries"
	} else {
		newMessage = fmt.Sprintf("stopping retries: %s", newMessage)
	}
	return fail.AbortedError(err, newMessage)
}

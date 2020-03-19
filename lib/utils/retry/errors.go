package retry

import (
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// ErrTimeout is used when a timeout occurs.
type ErrTimeout = scerr.ErrTimeout

// TimeoutError ...
func TimeoutError(err error, limit time.Duration) ErrTimeout {
	msg := fmt.Sprintf("retries timed out after %s", temporal.FormatDuration(limit))
	return scerr.TimeoutError(err, limit, msg)
}

// ErrLimit is used when a limit is reached.
type ErrLimit = scerr.ErrOverflow

// LimitError ...
func LimitError(err error, limit uint) ErrLimit {
	return scerr.OverflowError(err, limit, "retry limit exceeded")
}

// ErrStopRetry is returned when the context needs to stop the retries
type ErrStopRetry = scerr.ErrAborted

// StopRetryError ...
func StopRetryError(err error, msg ...interface{}) ErrStopRetry {
	newMessage := strprocess.FormatStrings(msg...)
	if newMessage == "" {
		newMessage = "stopping retries"
	} else {
		newMessage = fmt.Sprintf("stopping retries: %s", newMessage)
	}
	return scerr.AbortedError(newMessage, err)
}

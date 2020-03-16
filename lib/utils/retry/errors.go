package retry

import (
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// ErrTimeout is used when a timeout occurs.
type ErrTimeout = scerr.ErrTimeout

// TimeoutError ...
func TimeoutError(limit time.Duration, err error) ErrTimeout {
	msg := fmt.Sprintf("retries timed out after %s", temporal.FormatDuration(limit))
	return scerr.TimeoutError(msg, limit, err)
}

// ErrLimit is used when a limit is reached.
type ErrLimit = scerr.ErrOverflow

// LimitError ...
func LimitError(limit uint, err error) ErrLimit {
	return scerr.OverflowError("retry limit exceeded", limit, err)
}

// ErrStopRetry is returned when the context needs to stop the retries
type ErrStopRetry = scerr.ErrAborted

// StopRetryError ...
func StopRetryError(message string, err error) ErrStopRetry {
	newMessage := message
	if newMessage == "" {
		newMessage = "stopping retries"
	} else {
		newMessage = fmt.Sprintf("stopping retries: %s", message)
	}
	return scerr.AbortedError(newMessage, err)
}

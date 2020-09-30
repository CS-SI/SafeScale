package retry

import (
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// ErrTimeout is used when a timeout occurs.
type ErrTimeout = fail.ErrTimeout

// TimeoutError ...
func TimeoutError(limit time.Duration, err error) ErrTimeout {
	msg := fmt.Sprintf("retries timed out after %s", temporal.FormatDuration(limit))
	return fail.TimeoutError(msg, limit, err)
}

// ErrLimit is used when a limit is reached.
type ErrLimit = fail.ErrOverflow

// LimitError ...
func LimitError(limit uint, err error) ErrLimit {
	return fail.OverflowError("retry limit exceeded", limit, err)
}

// ErrAborted is returned when the context needs to stop the retries
type ErrAborted = fail.ErrAborted

// AbortedError ...
func AbortedError(message string, err error) ErrAborted {
	newMessage := message
	if newMessage == "" {
		newMessage = "stopping retries"
	} else {
		newMessage = fmt.Sprintf("stopping retries: %s", message)
	}
	return fail.AbortedError(newMessage, err)
}

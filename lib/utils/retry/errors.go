package retry

import (
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// ErrTimeout is an alias for utils.ErrTimeout
type ErrTimeout = scerr.ErrTimeout

// TimeoutError ...
func TimeoutError(limit time.Duration, err error) *scerr.ErrTimeout {
	msg := fmt.Sprintf("retries timed out after %s", temporal.FormatDuration(limit))
	return scerr.TimeoutError(msg, limit, err)
}

// ErrLimit is returned when the maximum attempts has been reached.
type ErrLimit = scerr.ErrLimit

// LimitError ...
func LimitError(limit uint, err error) *scerr.ErrLimit {
	return scerr.LimitError(limit, err)
}

// ErrAborted is returned when the context needs to stop the retries
type ErrAborted = scerr.ErrAborted

// AbortedError ...
func AbortedError(message string, err error) *scerr.ErrAborted {
	newMessage := message
	if newMessage == "" {
		newMessage = "stopping retries"
	} else {
		newMessage = fmt.Sprintf("stopping retries: %s", message)
	}
	return scerr.AbortedError(newMessage, err)
}

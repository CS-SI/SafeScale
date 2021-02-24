package retry

import (
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// ErrTimeout is used when a timeout occurs.
type ErrTimeout = fail.ErrTimeout

// TimeoutError ...
func TimeoutError(err error, limit time.Duration, options ...data.ImmutableKeyValue) *ErrTimeout {
	var (
		msg      string
		decorate bool
	)

	if len(options) > 0 {
		for _, v := range options {
			switch v.Key() { //nolint
			case "callstack":
				decorate = v.Value().(bool)
			}
		}
	}

	msg = fmt.Sprintf("retries timed out after %s", temporal.FormatDuration(limit))
	if decorate {
		msg = callstack.DecorateWith(msg, "", "", 0)
	}
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

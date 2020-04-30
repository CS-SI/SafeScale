package retry

import (
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// ErrTimeout is used when a timeout occurs.
type ErrTimeout = fail.Timeout

// TimeoutReport ...
func TimeoutError(err fail.Report, limit time.Duration) fail.Report {
	msg := fmt.Sprintf("retries timed out after %s", temporal.FormatDuration(limit))
	return fail.TimeoutReport(err, limit, msg)
}

// ErrLimit is used when a limit is reached.
type ErrLimit = fail.Overflow

// ErrLimitError ...
func LimitError(err fail.Report, limit uint) fail.Report {
	return fail.OverflowReport(err, limit, "retry limit exceeded")
}

// ErrStopRetry is returned when the context needs to stop the retries
type ErrStopRetry = fail.Aborted

// StopRetryError ...
func StopRetryError(err error, msg ...interface{}) fail.Report {
	newMessage := strprocess.FormatStrings(msg...)
	if newMessage == "" {
		newMessage = "stopping retries"
	} else {
		newMessage = fmt.Sprintf("stopping retries: %s", newMessage)
	}
	return fail.AbortedReport(err, newMessage)
}

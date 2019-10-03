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
func TimeoutError(limit time.Duration, err error) scerr.ErrTimeout {
	msg := fmt.Sprintf("retries timed out after %s", temporal.FormatDuration(limit))
	return scerr.TimeoutError(msg, limit, err)
}

// ErrLimit is returned when the maximum attempts has been reached.
type ErrLimit struct {
	scerr.ErrCore
	limit uint
}

// Cause returns the error cause
func (e ErrLimit) Cause() error {
	return e.ErrCore.Cause()
}

// Consequences returns the list of consequences
func (e ErrLimit) Consequences() []error {
	return e.ErrCore.Consequences()
}

// AddConsequence adds an error 'err' to the list of consequences
func (e ErrLimit) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// Error
func (e ErrLimit) Error() string {
	msg := fmt.Sprintf("retry limit exceeded after %d tries", e.limit)
	msgFinal := e.ErrCore.Error()
	if msgFinal != "" {
		msgFinal = msg + " + " + msgFinal
	} else {
		msgFinal = msg
	}

	msgFinal += e.ErrCore.CauseFormatter()

	return msgFinal
}

// LimitError ...
func LimitError(limit uint, err error) ErrLimit {
	return ErrLimit{
		ErrCore: scerr.NewErrCore("", err, []error{}),
		limit:   limit,
	}
}

// ErrStopRetry is returned when the maximum attempts has been reached.
type ErrStopRetry struct {
	scerr.ErrCore
}

// Cause returns the error cause
func (e ErrStopRetry) Cause() error {
	return e.ErrCore.Cause()
}

// Consequences returns the list of consequences
func (e ErrStopRetry) Consequences() []error {
	return e.ErrCore.Consequences()
}

// AddConsequence adds a consequence err to the list of consequences
func (e ErrStopRetry) AddConsequence(err error) error {
	e.ErrCore = e.ErrCore.Reset(e.ErrCore.AddConsequence(err))
	return e
}

// Error
func (e ErrStopRetry) Error() string {
	msgFinal := fmt.Sprintf("stopping retries because of: %v", e.Cause())

	return msgFinal
}

// StopRetryError ...
func StopRetryError(message string, err error) ErrStopRetry {
	return ErrStopRetry{
		ErrCore: scerr.NewErrCore(message, err, []error{}),
	}
}

package retry

import (
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	"google.golang.org/grpc/codes"
)

// ErrTimeout is an alias for utils.ErrTimeout
type ErrTimeout = scerr.ErrTimeout

// TimeoutError ...
func TimeoutError(limit time.Duration, err error) *scerr.ErrTimeout {
	msg := fmt.Sprintf("retries timed out after %s", temporal.FormatDuration(limit))
	return scerr.TimeoutError(msg, limit, err)
}

// ErrLimit is returned when the maximum attempts has been reached.
type ErrLimit = scerr.Error
type errLimit struct {
	core  scerr.Error
	limit uint
}

// Cause returns the error cause
func (e *errLimit) Cause() error {
	return e.core.Cause()
}

// Consequences returns the list of consequences
func (e *errLimit) Consequences() []error {
	return e.core.Consequences()
}

// CauseFormatter ...
func (e *errLimit) CauseFormatter() string {
	return e.core.CauseFormatter()
}

// FieldsFormatter ...
func (e *errLimit) FieldsFormatter() string {
	return e.core.FieldsFormatter()
}

// GRPCCode ...
func (e *errLimit) GRPCCode() codes.Code {
	return e.core.GRPCCode()
}

// ToGRPCStatus ...
func (e *errLimit) ToGRPCStatus() error {
	return e.core.ToGRPCStatus()
}

// Reset ...
func (e *errLimit) Reset(err error) scerr.Error {
	return e.core.Reset(err)
}

// WithField ...
func (e *errLimit) WithField(key string, value interface{}) scerr.Error {
	return e.core.WithField(key, value)
}

// AddConsequence adds an error 'err' to the list of consequences
func (e *errLimit) AddConsequence(err error) ErrLimit {
	e.core = e.core.Reset(e.core.AddConsequence(err))
	return e
}

// Error
func (e *errLimit) Error() string {
	msg := fmt.Sprintf("retry limit exceeded after %d tries", e.limit)
	coreMsg := e.core.Error()
	if coreMsg != "" {
		msg += ": " + coreMsg
	}
	msg += e.core.CauseFormatter()
	return msg
}

// LimitError ...
func LimitError(limit uint, err error) ErrLimit {
	retErr := &errLimit{limit: limit}
	retErr.core = scerr.NewError("", err, []error{})
	return retErr
}

// ErrAborted is returned when the context needs to stop the retries
type ErrAborted = scerr.ErrAborted

// AbortedError ...
func AbortedError(message string, err error) *scerr.ErrAborted {
	return scerr.AbortedError("stopping retries", err)
}

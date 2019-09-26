package retry

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/sirupsen/logrus"
	"time"
)

type ErrTimeout=utils.ErrTimeout

func AddConsequence(err error, cons error) error {
	type consequencer interface {
		Consequences() []error
		AddConsequence(error) error
		Error() string
	}

	if err != nil {
		conseq, ok := err.(consequencer)
		if ok {
			if cons != nil {
				nerr := conseq.AddConsequence(cons)
				return nerr
			}
			return conseq
		} else {
			logrus.Error(err)
		}
	}
	return err
}

func Consequences(err error) []error {
	type consequencer interface {
		Consequences() []error
		AddConsequence(error) error
		Error() string
	}

	if err != nil {
		conseq, ok := err.(consequencer)
		if ok {
			return conseq.Consequences()
		}
	}

	return []error{}
}


// TimeoutError ...
func TimeoutError(limit time.Duration, err error) utils.ErrTimeout {
	msg := fmt.Sprintf("retries timed out after %s", limit)
	return utils.TimeoutError(msg, limit, err)
}

// ErrLimit is returned when the maximum attempts has been reached.
type ErrLimit struct {
	utils.ErrCore
	limit uint
}

func (e ErrLimit) Cause() error {
	return e.ErrCore.Cause()
}

func (e ErrLimit) Consequences() []error {
	return e.ErrCore.Consequences()
}

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
		ErrCore: utils.NewErrCore("", err, []error{}),
		limit:   limit,
	}
}

// ErrStopRetry is returned when the maximum attempts has been reached.
type ErrStopRetry struct {
	utils.ErrCore
}

func (e ErrStopRetry) Cause() error {
	return e.ErrCore.Cause()
}

func (e ErrStopRetry) Consequences() []error {
	return e.ErrCore.Consequences()
}

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
		ErrCore: utils.NewErrCore(message, err, []error{}),
	}
}

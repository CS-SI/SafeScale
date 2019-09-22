package retry

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"time"
)

type errBase struct {
	msgs []string
}

func (b errBase) Plus(err string) {
	if err != "" {
		b.msgs = append(b.msgs, err)
	}
}

func (b errBase) Error() string {
	var message string
	for _, m := range b.msgs {
		if message != "" {
			message += " + "
		}
		message += m
	}
	return message
}

// ErrTimeout is returned when the time limit has been reached.
type ErrTimeout struct {
	b            errBase
	cause        error
	consequences []error
	limit        time.Duration
}

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

func (e ErrTimeout) Consequences() []error {
	return e.consequences
}

func (e ErrTimeout) AddConsequence(err error) error {
	if e.consequences == nil {
		e.consequences = []error{}
	}
	e.consequences = append(e.consequences, err)
	return e
}

func (e ErrTimeout) Error() string {
	msgFinal := e.b.Error()
	msg := fmt.Sprintf("retries timed out after %s", e.limit)
	if msgFinal != "" {
		msgFinal = msg + " + " + msgFinal
	} else {
		msgFinal = msg
	}
	return msgFinal
}

func (e ErrTimeout) Cause() error {
	return e.cause
}

// TimeoutError ...
func TimeoutError(limit time.Duration, err error) ErrTimeout {
	return ErrTimeout{
		limit:        limit,
		cause:        err,
		consequences: []error{},
	}
}

// ErrLimit is returned when the maximum attempts has been reached.
type ErrLimit struct {
	b            errBase
	cause        error
	consequences []error
	limit        uint
}

func (e ErrLimit) Cause() error {
	return e.cause
}

func (e ErrLimit) Consequences() []error {
	return e.consequences
}

func (e ErrLimit) AddConsequence(err error) error {
	if e.consequences == nil {
		e.consequences = []error{}
	}
	e.consequences = append(e.consequences, err)
	return e
}

// Error
func (e ErrLimit) Error() string {
	msg := fmt.Sprintf("retry limit exceeded after %d tries", e.limit)
	msgFinal := e.b.Error()
	if msgFinal != "" {
		msgFinal = msg + " + " + msgFinal
	} else {
		msgFinal = msg
	}
	return msgFinal
}

// LimitError ...
func LimitError(limit uint, err error) ErrLimit {
	return ErrLimit{
		cause:        err,
		limit:        limit,
		consequences: []error{},
	}
}

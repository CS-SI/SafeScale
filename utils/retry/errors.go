package retry

import (
	"fmt"
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
	b     errBase
	limit time.Duration
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

// ErrLimit is returned when the maximum attempts has been reached.
type ErrLimit struct {
	b     errBase
	limit uint
}

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

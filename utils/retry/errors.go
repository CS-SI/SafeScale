package retry

import (
	"fmt"
	"time"
)

type baseError struct {
	msgs []string
}

func (b baseError) Plus(err string) {
	if err != "" {
		b.msgs = append(b.msgs, err)
	}
}

func (b baseError) Error() string {
	var message string
	for _, m := range b.msgs {
		if message != "" {
			message += " + "
		}
		message += m
	}
	return message
}

// TimeoutError is returned when the time limit has been reached.
type TimeoutError struct {
	b     baseError
	limit time.Duration
}

func (e TimeoutError) Error() string {
	msgFinal := e.b.Error()
	msg := fmt.Sprintf("retry timed out after %s", e.limit)
	if msgFinal != "" {
		msgFinal = msg + " + " + msgFinal
	} else {
		msgFinal = msg
	}
	return msgFinal
}

// MaxError is returned when the maximum attempts has been reached.
type MaxError struct {
	b     baseError
	limit uint
}

func (e MaxError) Error() string {
	msg := fmt.Sprintf("retry limit exceeded after %d tries", e.limit)
	msgFinal := e.b.Error()
	if msgFinal != "" {
		msgFinal = msg + " + " + msgFinal
	} else {
		msgFinal = msg
	}
	return msgFinal
}

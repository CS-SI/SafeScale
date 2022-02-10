package net

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type RetryableErrorInterface interface {
	error
	Timeout() bool
	Temporary() bool
}
type RetryableError struct {
	message string
	RetryableErrorInterface
}

func (e *RetryableError) Timeout() bool {
	return false
}
func (e *RetryableError) Temporary() bool {
	return true
}
func (e *RetryableError) Error() string {
	return e.message
}
func NewRetryableError(msg string) *RetryableError {
	return &RetryableError{
		message: msg,
	}
}

func Test_WhileUnsuccessfulButRetryable(t *testing.T) {

	// no waitfor
	var (
		callback func() error = func() error {
			return errors.New("Any error")
		}
		waitfor *retry.Officer = nil
		timeout time.Duration  = 0 * time.Second
		err     error
	)

	err = WhileUnsuccessfulButRetryable(callback, waitfor, timeout)
	require.NotEqual(t, err, nil)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.EqualValues(t, strings.Contains(err.Error(), "invalid parameter waitor"), true)
	require.EqualValues(t, strings.Contains(err.Error(), "cannot be nil"), true)

	// no timeout
	waitfor = retry.Randomized(50*time.Millisecond, 500*time.Millisecond)
	timeout = -1 * time.Second
	callback = func() error {
		return fail.TimeoutError(errors.New("Hard timeout"), 1*time.Second, "Any error")
	}
	err = WhileUnsuccessfulButRetryable(callback, waitfor, timeout)
	require.NotEqual(t, err, nil)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrTimeout")
	require.EqualValues(t, strings.Contains(err.Error(), "stopping retries"), true)
	require.EqualValues(t, strings.Contains(err.Error(), "Hard timeout"), true)
	require.EqualValues(t, strings.Contains(err.Error(), "Any error"), true)

	// Success one
	waitfor = retry.Linear(50 * time.Millisecond)
	timeout = 5 * time.Second
	callback = func() error {
		return nil
	}
	err = WhileUnsuccessfulButRetryable(callback, waitfor, timeout)
	require.EqualValues(t, err, nil)

	// Multiple fail before success
	waitfor = retry.Linear(10 * time.Millisecond)
	timeout = 5 * time.Second
	callback = func() error {
		return nil
	}
	err = WhileUnsuccessfulButRetryable(callback, waitfor, timeout)
	require.EqualValues(t, err, nil)

	maxTries := 8
	tries := 0
	callback = func() error {
		tries = tries + 1
		if tries >= maxTries {
			return nil
		}
		return NewRetryableError(fmt.Sprintf("Miss but retry (%d/%d)", tries, maxTries))
	}
	err = WhileUnsuccessfulButRetryable(callback, waitfor, timeout)
	require.EqualValues(t, err, nil)
	require.EqualValues(t, tries, maxTries)

	// Multiple fail before fail
	waitfor = retry.Linear(10 * time.Millisecond)
	timeout = 5 * time.Second
	callback = func() error {
		return nil
	}
	err = WhileUnsuccessfulButRetryable(callback, waitfor, timeout)
	require.EqualValues(t, err, nil)

	maxTries = 8
	tries = 0
	callback = func() error {
		tries = tries + 1
		if tries >= maxTries {
			return retry.StopRetryError(errors.New("Too much tries"))
		}
		return NewRetryableError(fmt.Sprintf("Miss but retry (%d/%d)", tries, maxTries))
	}
	err = WhileUnsuccessfulButRetryable(callback, waitfor, timeout)
	require.NotEqual(t, err, nil)
	require.EqualValues(t, strings.Contains(err.Error(), "stopping retries"), true)
	require.EqualValues(t, strings.Contains(err.Error(), "Too much tries"), true)
	require.EqualValues(t, tries, maxTries)

}

//------------------------------------------------

type MyError struct {
	error
	temporal bool
}

func NewMyError(error error, temporal bool) *MyError {
	return &MyError{error: error, temporal: temporal}
}

func (e MyError) Timeout() bool {
	return true
}

func (e MyError) Temporary() bool {
	return e.temporal
}

func (e MyError) Error() string {
	return ""
}

func Test_normalizeErrorAndCheckIfRetriable(t *testing.T) {
	type args struct {
		in  error
		out error
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"std error", args{in: fmt.Errorf("something"), out: retry.StopRetryError(fmt.Errorf("something"))}, true},
		{
			"not avail", args{in: fail.NotAvailableError("nice try"), out: fmt.Errorf("nice try")}, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := normalizeErrorAndCheckIfRetriable(tt.args.in); (err != nil) != tt.wantErr || (err != tt.args.out) {
				if err != nil && err != tt.args.out {
					if !assert.ObjectsAreEqualValues(err.Error(), tt.args.out.Error()) {
						t.Errorf("normalizeErrorAndCheckIfRetriable() wanted = '%v', actually = '%v'", tt.args.out, err)
					}
				}
				if (err != nil) != tt.wantErr {
					t.Errorf("normalizeErrorAndCheckIfRetriable() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
			if urr := oldNormalizeErrorAndCheckIfRetriable(tt.args.in); (urr != nil) != tt.wantErr || (urr != tt.args.out) {
				if urr != nil && urr != tt.args.out {
					if !assert.ObjectsAreEqualValues(urr.Error(), tt.args.out.Error()) {
						t.Errorf("oldNormalizeErrorAndCheckIfRetriable() wanted = '%v', actually = '%v'", tt.args.out, urr)
					}
				}
				if (urr != nil) != tt.wantErr {
					t.Errorf("oldNormalizeErrorAndCheckIfRetriable() error = %v, wantErr %v", urr, tt.wantErr)
				}
			}
		})
	}
}

func Test_normalizeErrorImprovedAndCheckIfRetriable(t *testing.T) {
	type args struct {
		in  error
		out error
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"temporal net error", args{in: NewMyError(fmt.Errorf("encrypted"), true), out: NewMyError(fmt.Errorf("encrypted"), true)}, true},
		{"final net error", args{in: NewMyError(fmt.Errorf("encrypted"), false), out: retry.StopRetryError(NewMyError(fmt.Errorf("encrypted"), false))}, true},
		{"crafted url error", args{in: &url.Error{
			Op:  "something",
			URL: "www.google.com",
			Err: nil,
		}, out: retry.StopRetryError(&url.Error{
			Op:  "something",
			URL: "www.google.com",
			Err: nil,
		})}, true},
		{"crafted url error with reason", args{in: &url.Error{
			Op:  "something",
			URL: "www.google.com",
			Err: fmt.Errorf("it was DNS"),
		}, out: retry.StopRetryError(&url.Error{
			Op:  "something",
			URL: "www.google.com",
			Err: fmt.Errorf("it was DNS"),
		})}, true},
		{
			"not avail", args{in: fail.NotAvailableError("nice try"), out: fmt.Errorf("nice try")}, true,
		},
		{
			"not avail ptr", args{in: *fail.NotAvailableError("nice try"), out: fmt.Errorf("nice try")}, true,
		},
		{
			"not avail with cause", args{in: fail.NotAvailableErrorWithCause(fmt.Errorf("out of time"), "nice try"), out: retry.StopRetryError(fmt.Errorf("nice try: out of time"))}, true,
		},
		{
			"not avail ptr with cause", args{in: *fail.NotAvailableErrorWithCause(fmt.Errorf("out of time"), "nice try"), out: retry.StopRetryError(fmt.Errorf("nice try: out of time"))}, true,
		},
		{
			"overflow", args{in: fail.OverflowError(nil, 0, "nice try"), out: fmt.Errorf("nice try")}, true,
		},
		{
			"overflow ptr", args{in: *fail.OverflowError(nil, 0, "nice try"), out: fmt.Errorf("nice try")}, true,
		},
		{
			"overflow with cause", args{in: fail.OverflowError(fmt.Errorf("nice try"), 0, "ouch"), out: retry.StopRetryError(fmt.Errorf("ouch: nice try"))}, true,
		},
		{
			"overflow ptr with cause", args{in: *fail.OverflowError(fmt.Errorf("nice try"), 0, "ouch"), out: retry.StopRetryError(fmt.Errorf("ouch: nice try"))}, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := normalizeErrorAndCheckIfRetriable(tt.args.in); (err != nil) != tt.wantErr || (err != tt.args.out) {
				if err != nil && err != tt.args.out {
					if !assert.ObjectsAreEqualValues(err.Error(), tt.args.out.Error()) {
						t.Errorf("normalizeErrorAndCheckIfRetriable() wanted = '%v', actually = '%v'", tt.args.out, err)
					}
				}
				if (err != nil) != tt.wantErr {
					t.Errorf("normalizeErrorAndCheckIfRetriable() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

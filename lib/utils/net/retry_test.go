/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"
	"syscall"
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
	require.EqualValues(t, strings.Contains(err.Error(), "invalid parameter waiter"), true)
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

	// Multiple fail before fail (retry.StopRetryError)
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
			return fail.AbortedError(errors.New("Too much tries"), "Stop trying")
		}
		return NewRetryableError(fmt.Sprintf("Miss but retry (%d/%d)", tries, maxTries))
	}
	err = WhileUnsuccessfulButRetryable(callback, waitfor, timeout)
	require.NotEqual(t, err, nil)
	// TODO: Here should return fail.ErrAborted but return *fail.ErrorCore
	// require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrAborted")
	require.EqualValues(t, strings.Contains(err.Error(), "stopping retries"), true)
	require.EqualValues(t, strings.Contains(err.Error(), "Too much tries"), true)
	require.EqualValues(t, tries, maxTries)

	// Multiple fail before fail (retry.ErrTimeout)
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
			return fail.TimeoutError(errors.New("Too much tries"), 30*time.Second, "Stop trying")
		}
		return NewRetryableError(fmt.Sprintf("Miss but retry (%d/%d)", tries, maxTries))
	}
	err = WhileUnsuccessfulButRetryable(callback, waitfor, timeout)
	require.NotEqual(t, err, nil)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrTimeout")
	require.EqualValues(t, strings.Contains(err.Error(), "stopping retries"), true)
	require.EqualValues(t, strings.Contains(err.Error(), "Too much tries"), true)
	require.EqualValues(t, tries, maxTries)

	// Multiple fail before fail (any)
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
			return errors.New("Too much tries")
		}
		return NewRetryableError(fmt.Sprintf("Miss but retry (%d/%d)", tries, maxTries))
	}
	err = WhileUnsuccessfulButRetryable(callback, waitfor, timeout)
	require.NotEqual(t, err, nil)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.errorCore")
	require.EqualValues(t, strings.Contains(err.Error(), "stopping retries"), true)
	require.EqualValues(t, strings.Contains(err.Error(), "Too much tries"), true)
	require.EqualValues(t, tries, maxTries)

}

func Test_WhileCommunicationUnsuccessfulDelay1Second(t *testing.T) {

	maxTries := 4
	tries := 0
	callback := func() error {
		tries = tries + 1
		if tries >= maxTries {
			return nil
		}
		return NewRetryableError(fmt.Sprintf("Miss but retry (%d/%d)", tries, maxTries))
	}
	err := WhileCommunicationUnsuccessfulDelay1Second(callback, 5*time.Second)
	require.EqualValues(t, err, nil)
	require.EqualValues(t, tries, maxTries)

}

type normalizeErrorTest struct {
	in  error
	out string
}

type NetErrorTemporaryInterface interface {
	net.Error
	Timeout() bool
	Temporary() bool
}
type NetErrorTemporary struct {
	NetErrorTemporaryInterface
}

func (e *NetErrorTemporary) Timeout() bool {
	return false
}
func (e *NetErrorTemporary) Temporary() bool {
	return true
}
func NewNetErrorTemporary() *NetErrorTemporary {
	return &NetErrorTemporary{}
}

func getLocalNetAddr() net.Addr {

	var fallback net.Addr = nil
	var selected net.Addr = nil

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if fallback == nil {
				fallback = addr
			}
			if !strings.Contains(addr.String(), "127.0.0.1") &&
				!strings.Contains(addr.String(), "::1") &&
				!strings.Contains(addr.String(), "172.17.0.1") &&
				!strings.Contains(addr.String(), "::ffff:ac11:1") {
				selected = addr
				break
			}
		}
		if selected != nil {
			break
		}
	}
	if selected != nil {
		return selected
	}
	return fallback

}

func Test_normalizeErrorAndCheckIfRetriable2(t *testing.T) {

	addr := getLocalNetAddr()

	tests := []normalizeErrorTest{
		{
			in: &url.Error{
				Op:  "read",
				URL: "https://nowhere.com",
				Err: NewRetryableError("URL Target does not exists"), // Temporary = true
			},
			out: "*url.Error",
		},
		{
			in: &url.Error{
				Op:  "read",
				URL: "https://nowhere.com",
				Err: errors.New("URL Target does not exists"), // Temporary = false
			},
			out: "*fail.ErrAborted",
		},
		{
			in: &net.OpError{
				Op:     "read",
				Net:    "tcp",
				Source: addr,
				Addr:   addr,
				Err:    net.Error(syscall.ECONNRESET), // IsConnectionReset = true
			},
			out: "*net.OpError",
		},
		{
			in: &net.OpError{
				Op:     "read",
				Net:    "tcp",
				Source: addr,
				Addr:   addr,
				Err:    NewRetryableError("URL Target does not exists"), // IsConnectionReset = false, Temporary = true
			},
			out: "*net.OpError",
		},
		{
			in: &net.OpError{
				Op:     "read",
				Net:    "tcp",
				Source: addr,
				Addr:   addr,
				Err:    errors.New("Any error"), // IsConnectionReset = false, Temporary = false
			},
			out: "*fail.ErrAborted",
		},
		{
			in:  net.Error(NewRetryableError("Again buddy, try again !!!")), // Temporary = true
			out: "*net.RetryableError",
		},
		{
			in:  net.Error(syscall.ECONNRESET), // Temporary = true ? => @TODO: Should not it be consider as retrybable ?
			out: "*fail.ErrAborted",
		},
		{
			in:  net.Error(syscall.ECONNREFUSED), // Temporary = false
			out: "*fail.ErrAborted",
		},
		{
			in: fail.NotAvailableErrorWithCause(
				&url.Error{
					Op:  "read",
					URL: "https://nowhere.com",
					Err: NewRetryableError("URL Target does not exists"), // Temporary = true ? => @TODO: Should not it be consider as retrybable ?
				},
				nil,
				"Any error",
			),
			out: "*fail.ErrInvalidRequest",
		},
		{
			in: fail.NotAvailableErrorWithCause(
				&url.Error{
					Op:  "read",
					URL: "https://nowhere.com",
					Err: errors.New("Any error"), // Temporary = false
				},
				nil,
				"Any error",
			),
			out: "*fail.ErrAborted",
		},
		{
			in: fail.NotAvailableErrorWithCause(
				NewNetErrorTemporary(), // as Net.Error with Temporary = true ? => @TODO: Should not it be consider as retrybable ?
				nil,
				"Any error",
			),
			out: "*fail.ErrNotAvailable",
		},
		{
			in: fail.NotAvailableErrorWithCause(
				net.Error(syscall.ECONNREFUSED), // Temporary = false
				nil,
				"Any error",
			),
			out: "*fail.ErrAborted",
		},
		{
			in: fail.NotAvailableErrorWithCause(
				fail.NotAvailableError("Any cause"), // Temporary = false
				nil,
				"Any error",
			),
			out: "*fail.ErrNotAvailable",
		},
		{
			in: fail.NotAvailableErrorWithCause(
				errors.New("Any cause"), // Temporary = false
				nil,
				"Any error",
			),
			out: "*fail.ErrAborted",
		},
		{
			in:  errors.New("not found"),
			out: "*fail.ErrNotFound",
		},
		{
			in:  errors.New("dial tcp:"),
			out: "*fail.ErrNotAvailable",
		},
		{
			in:  errors.New("EOF"),
			out: "*fail.ErrNotAvailable",
		},
		{
			in:  errors.New("Any error"),
			out: "*fail.ErrAborted",
		},
	}

	for i := range tests {
		test := tests[i]
		result := normalizeErrorAndCheckIfRetriable(true, test.in)

		if reflect.TypeOf(result).String() != test.out {
			t.Error(fmt.Sprintf("Invalid normalizeErrorAndCheckIfRetriable %d convert:\n    expect %s => %s\n    has %s => %s", i, reflect.TypeOf(test.in).String(), test.out, reflect.TypeOf(test.in).String(), reflect.TypeOf(result).String()))
			t.Fail()
		}
	}

}

func Test_normalizeErrorAndCheckIfRetriable3(t *testing.T) {

	tests := []normalizeErrorTest{
		{
			in: fail.NotAvailableErrorWithCause(
				&url.Error{
					Op:  "read",
					URL: "https://nowhere.com",
					Err: errors.New("URL Target does not exists"), // Temporary = true ? => @TODO: Should not it be consider as retrybable ?
				},
				nil,
				"Any error",
			),
			out: "*fail.ErrAborted",
		},
	}

	for i := range tests {
		test := tests[i]
		result := normalizeErrorAndCheckIfRetriable(true, test.in)

		if reflect.TypeOf(result).String() != test.out {
			t.Error(fmt.Sprintf("Invalid normalizeErrorAndCheckIfRetriable %d convert:\n    expect %s => %s\n    has %s => %s", i, reflect.TypeOf(test.in).String(), test.out, reflect.TypeOf(test.in).String(), reflect.TypeOf(result).String()))
			t.Fail()
		}
	}

}

// -------------------------------------------------------------------------------------------

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
			if err := normalizeErrorAndCheckIfRetriable(false, tt.args.in); (err != nil) != tt.wantErr || (err != tt.args.out) {
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
			"not avail with cause", args{in: fail.NotAvailableErrorWithCause(fmt.Errorf("out of time"), nil, "nice try"), out: retry.StopRetryError(fmt.Errorf("nice try: out of time"))}, true,
		},
		{
			"not avail ptr with cause", args{in: *fail.NotAvailableErrorWithCause(fmt.Errorf("out of time"), nil, "nice try"), out: retry.StopRetryError(fmt.Errorf("nice try: out of time"))}, true,
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
			if err := normalizeErrorAndCheckIfRetriable(false, tt.args.in); (err != nil) != tt.wantErr || (err != tt.args.out) {
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

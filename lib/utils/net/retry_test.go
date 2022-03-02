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

	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/retry"
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
		callback = func() error {
			return errors.New("Any error")
		}
		waitfor *retry.Officer = nil
		timeout                = 0 * time.Second
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

func Test_normalizeErrorAndCheckIfRetriable(t *testing.T) {

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
				[]error{},
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
				[]error{},
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
			t.Error(fmt.Sprintf("Invalid normalizeErrorAndCheckIfRetriable convert:\n    expect %s => %s\n    has %s => %s", reflect.TypeOf(test.in).String(), test.out, reflect.TypeOf(test.in).String(), reflect.TypeOf(result).String()))
			t.Fail()
		}
	}

}

func Test_oldNormalizeErrorAndCheckIfRetriable(t *testing.T) {

	addr := getLocalNetAddr()

	tests := []normalizeErrorTest{
		{
			in: &url.Error{
				Op:  "read",
				URL: "https://nowhere.com",
				Err: NewRetryableError("URL Target does not exists"), // Temporary = true
			},
			out: "*fail.ErrInvalidRequest",
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
			out: "*fail.ErrAborted",
		},
		{
			in: &net.OpError{
				Op:     "read",
				Net:    "tcp",
				Source: addr,
				Addr:   addr,
				Err:    NewRetryableError("URL Target does not exists"), // IsConnectionReset = false, Temporary = true
			},
			out: "*fail.ErrAborted",
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
			out: "*fail.ErrAborted",
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
				[]error{},
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
				[]error{},
				"Any error",
			),
			out: "*fail.ErrAborted",
		},
		{
			in: fail.NotAvailableErrorWithCause(
				nil,
				[]error{},
				"Any error",
			),
			out: "*fail.ErrNotAvailable",
		},
		{
			in: fail.NotFoundErrorWithCause(
				nil,
				[]error{},
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
			out: "*fail.ErrNotAvailable",
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
			out: "*fail.ErrNotAvailable",
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
		{
			in:  nil,
			out: "",
		},
	}

	for i := range tests {
		test := tests[i]
		result := oldNormalizeErrorAndCheckIfRetriable(test.in)
		if result == nil {
			if test.out != "" {
				t.Error(fmt.Sprintf("Invalid oldNormalizeErrorAndCheckIfRetriable convert:\n    expect nil => nil\n    has nil => %s", reflect.TypeOf(result).String()))
				t.Fail()
			}
		} else {
			if reflect.TypeOf(result).String() != test.out {
				t.Error(fmt.Sprintf("Invalid oldNormalizeErrorAndCheckIfRetriable convert:\n    expect %s => %s\n    has %s => %s", reflect.TypeOf(test.in).String(), test.out, reflect.TypeOf(test.in).String(), reflect.TypeOf(result).String()))
				t.Fail()
			}
		}
	}

}

type normalizeURLErrorTest struct {
	in  *url.Error
	out string
}

func Test_normalizeURLError(t *testing.T) {

	result := normalizeURLError(nil)
	require.EqualValues(t, result, nil)

	tests := []normalizeURLErrorTest{
		{
			in: &url.Error{
				Op:  "read",
				URL: "https://nowhere.com",
				Err: errors.New("Any error"), // Temporary = false
			},
			out: "*fail.ErrAborted",
		},
		/* TODO: *url.Error can't be *net.DNSError, fix normalizeURLError header
		{
			in: &net.DNSError{
				Err:          "DNSError err",
				Name:         "DNSError name",
				Server:       "DNSError server",
				IsTimeout:    false,
				IsTemporary:  true,
				IsNoSuchHost: true, // if true, host could not be found
			},
			out: "*fail.ErrInvalidRequest",
		},
		*/
		{
			in: &url.Error{
				Op:  "read",
				URL: "https://nowhere.com",
				Err: NewNetErrorTemporary(), // Temporary = true
			},
			out: "*fail.ErrInvalidRequest",
		},
		{
			in: &url.Error{
				Op:  "read",
				URL: "https://nowhere.com",
				Err: NewRetryableError("Any error"), // Temporary = true
			},
			out: "*fail.ErrInvalidRequest",
		},
		{
			in: &url.Error{
				Op:  "read",
				URL: "https://nowhere.com",
				Err: nil,
			},
			out: "*fail.ErrAborted",
		},
	}

	for i := range tests {
		test := tests[i]
		result := normalizeURLError(test.in)
		if result == nil {
			if test.out != "" {
				t.Error(fmt.Sprintf("Invalid normalizeURLError convert:\n    expect nil => nil\n    has nil => %s", reflect.TypeOf(result).String()))
				t.Fail()
			}
		} else {
			if reflect.TypeOf(result).String() != test.out {
				t.Error(fmt.Sprintf("Invalid normalizeURLError convert:\n    expect %s => %s\n    has %s => %s", reflect.TypeOf(test.in).String(), test.out, reflect.TypeOf(test.in).String(), reflect.TypeOf(result).String()))
				t.Fail()
			}
		}
	}

}

func Test_erz(t *testing.T) {

	result := erz(net.Error(syscall.ECONNREFUSED))
	require.EqualValues(t, result, 111)

	result = erz(net.Error(syscall.ECONNRESET))
	require.EqualValues(t, result, 104)

	result = erz(net.Error(syscall.ECONNABORTED))
	require.EqualValues(t, result, 103)

	result = erz(errors.New("Any error"))
	require.EqualValues(t, result, 0)

}

func Test_IsConnectionReset(t *testing.T) {

	result := IsConnectionReset(errors.New("Any error"))
	require.EqualValues(t, result, false)

	result = IsConnectionReset(net.Error(syscall.ECONNRESET))
	require.EqualValues(t, result, true)

}

func Test_IsConnectionRefused(t *testing.T) {

	result := IsConnectionRefused(errors.New("Any error"))
	require.EqualValues(t, result, false)

	result = IsConnectionRefused(net.Error(syscall.ECONNREFUSED))
	require.EqualValues(t, result, true)

}

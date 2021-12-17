/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"net"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
)

// WhileUnsuccessfulButRetryable executes callback inside a retry loop with tolerance for communication errors (relative to net package),
// or some fail.Error that are considered retryable: asking "waitor" to wait between each try, with a duration limit of 'timeout'.
func WhileUnsuccessfulButRetryable(callback func() error, waitor *retry.Officer, timeout time.Duration) fail.Error {
	if waitor == nil {
		return fail.InvalidParameterCannotBeNilError("waitor")
	}

	var arbiter retry.Arbiter
	if timeout <= 0 {
		arbiter = retry.Unsuccessful()
	} else {
		arbiter = retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(timeout))
	}

	xerr := retry.Action(
		func() (nested error) {
			defer fail.OnPanic(&nested)
			callbackErr := callback()
			actionErr := normalizeErrorAndCheckIfRetriable(callbackErr)
			return actionErr
		},
		arbiter,
		waitor,
		nil,
		nil,
		func(t retry.Try, v verdict.Enum) {
			switch v {
			case verdict.Retry:
				logrus.Warnf("communication failed (%s), retrying", t.Err.Error())
			default:
			}
		},
	)
	if xerr != nil {
		switch realErr := xerr.(type) {
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(realErr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(fail.Cause(realErr), "timeout")
		default:
			return xerr
		}
	}
	return nil
}

// WhileCommunicationUnsuccessfulDelay1Second executes callback inside a retry loop with tolerance for communication errors (relative to net package),
// waiting 1 second between each try, with a limit of 'timeout'
func WhileCommunicationUnsuccessfulDelay1Second(callback func() error, timeout time.Duration) fail.Error {
	return WhileUnsuccessfulButRetryable(callback, retry.Constant(temporal.MinDelay()), timeout)
}

// normalizeErrorAndCheckIfRetriable analyzes the error passed as parameter and rewrite it to be more explicit
// If the error is not a communication error, we return a *retry.ErrAborted error
// containing the causing error in it
func normalizeErrorAndCheckIfRetriable(in error) (err error) {
	// VPL: see if we could replace this defer with retry notification ability in retryOnCommunicationFailure
	defer func() {
		if err != nil {
			switch err.(type) {
			case fail.ErrInvalidRequest, *fail.ErrInvalidRequest:
				logrus.Warnf(err.Error())
			default:
				debug.IgnoreError(err)
			}
		}
	}()

	if in != nil {
		switch realErr := in.(type) {
		case *url.Error:
			if realErr.Temporary() {
				return realErr
			}
			return normalizeURLError(realErr)
		case *net.OpError: // reset-by-peer errors will be captured here
			if IsConnectionReset(realErr) { // give a chance to reset-by-peer errors
				return realErr
			}
			if realErr.Temporary() {
				return realErr
			}
			return retry.StopRetryError(realErr)
		case net.Error:
			if realErr.Temporary() {
				return realErr
			}
			return retry.StopRetryError(realErr)
		case fail.Error, fail.ErrNotAvailable, fail.ErrOverflow, fail.ErrOverload: // a fail.Error may contain a cause of type net.Error, being *url.Error a special subcase.
			// net.Error, and by extension url.Error have methods to check if the error is temporary -Temporary()-, or it's a timeout -Timeout()-, we should use the information to make decisions
			// In this case, handle those net.Error accordingly
			cause := fail.Cause(realErr)
			switch thecause := cause.(type) {
			case *url.Error:
				return normalizeURLError(thecause)
			case net.Error:
				if thecause.Temporary() {
					return realErr
				}
				return retry.StopRetryError(realErr)
			case *fail.ErrNotAvailable, fail.ErrNotAvailable, *fail.ErrOverflow, fail.ErrOverflow, *fail.ErrOverload, fail.ErrOverload:
				return realErr
			default:
				return retry.StopRetryError(realErr)
			}
		default:
			// doing something based on error's Error() method is always dangerous, so a little log here might help finding problems later
			logrus.Tracef("trying to normalize based on Error() string of: (%s): %v", reflect.TypeOf(in).String(), in)
			// VPL: this part is here to workaround limitations of Stow in error handling... Should be replaced/removed when Stow will be replaced... one day...
			str := in.Error()
			switch str {
			case "not found": // stow may return that error message if it does not find something
				return fail.NotFoundError("not found")
			default: // stow may return an error containing "dial tcp:" for some HTTP errors
				if strings.Contains(str, "dial tcp:") {
					return fail.NotAvailableError(str)
				}
				if strings.Contains(str, "EOF") { // stow may return that error message if comm fails
					return fail.NotAvailableError("encountered end-of-file")
				}
				// In any other case, the error should explain the retry has to stop
				return retry.StopRetryError(in)
			}
		}
	}
	return nil
}

// normalizeErrorAndCheckIfRetriable analyzes the error passed as parameter and rewrite it to be more explicit
// If the error is not a communication error, we return a *retry.ErrAborted error
// containing the causing error in it
func oldNormalizeErrorAndCheckIfRetriable(in error) (err error) {
	defer func() {
		if err != nil {
			switch err.(type) {
			case fail.ErrInvalidRequest, *fail.ErrInvalidRequest:
				logrus.Warnf(err.Error())
			default:
				debug.IgnoreError(err)
			}
		}
	}()

	if in != nil {
		switch realErr := in.(type) {
		case *url.Error:
			return normalizeURLError(realErr)
		case fail.Error: // a fail.Error may contain a cause of type net.Error, being *url.Error a special subcase.
			// net.Error, and by extension url.Error have methods to check if the error is temporary -Temporary()-, or it's a timeout -Timeout()-, we should use the information to make decisions

			// In this case, handle those net.Error accordingly
			if realErr.Cause() != nil {
				switch cause := realErr.Cause().(type) { // nolint
				case *url.Error:
					return normalizeURLError(cause)
				case net.Error:
					return realErr
				// If error is *fail.ErrNotAvailable, *fail.ErrOverflow or *fail.ErrOverload, leave a chance to retry
				case *fail.ErrNotAvailable, fail.ErrNotAvailable, *fail.ErrOverflow, fail.ErrOverflow, *fail.ErrOverload, fail.ErrOverload:
					return realErr
				}
			} else {
				switch realErr.(type) { // nolint
				// If error is *fail.ErrNotAvailable, *fail.ErrOverflow or *fail.ErrOverload, leave a chance to retry
				case *fail.ErrNotAvailable, *fail.ErrOverflow, *fail.ErrOverload:
					return realErr
				case net.Error: // this also covers *url.Error, if the URL needs a specific error treatment, add a case BEFORE this line
					return realErr
				}
			}

			// If error is *fail.ErrNotAvailable, *fail.ErrOverflow or *fail.ErrOverload, leave a chance to retry
			switch realErr.(type) {
			case *fail.ErrNotAvailable, *fail.ErrOverflow, *fail.ErrOverload:
				return realErr
			default:
				return retry.StopRetryError(realErr)
			}
		default:
			// doing something based on error's Error() method is always dangerous, so a litte log here might help finding problems later
			logrus.Tracef("trying to normalize based on Error() string of: (%s): %v", reflect.TypeOf(in).String(), in)
			// VPL: this part is here to workaround limitations of Stow in error handling... Should be replaced/removed when Stow will be replaced... one day...
			str := in.Error()
			switch str {
			case "not found": // stow may return that error message if it does not find something
				return fail.NotFoundError("not found")
			default: // stow may return an error containing "dial tcp:" for some HTTP errors
				if strings.Contains(str, "dial tcp:") {
					logrus.Tracef("encountered 'dial tcp' error")
					return fail.NotAvailableError(str)
				}
				if strings.Contains(str, "EOF") { // stow may return that error message if comm fails
					logrus.Tracef("encountered end-of-file")
					return fail.NotAvailableError("encountered end-of-file")
				}
				// In any other case, the error should explain the retry has to stop
				return retry.StopRetryError(in)
			}
		}
	}
	return nil
}

func normalizeURLError(err *url.Error) fail.Error {
	if err == nil {
		return nil
	}

	isTemporary := err.Temporary()

	if err.Err != nil {
		switch commErr := err.Err.(type) {
		case *net.DNSError:
			if isTemporary {
				return fail.InvalidRequestError("failed to resolve by DNS: %v", commErr)
			}
			return retry.StopRetryError(commErr, "failed to resolve by DNS")
		default:
			if isTemporary {
				if commErr != nil {
					return fail.InvalidRequestError("failed to communicate (error type: %s): %v", reflect.TypeOf(commErr).String(), commErr)
				}
				return fail.InvalidRequestError("failed to communicate: %v", commErr)
			}
			return retry.StopRetryError(err)
		}
	}

	return retry.StopRetryError(err)
}

func erz(v error) uintptr {
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Uintptr {
		return uintptr(rv.Uint())
	}
	return 0
}

// IsConnectionReset returns true if given err is a "reset by peer" error
func IsConnectionReset(err error) bool {
	if runtime.GOOS == "windows" {
		const WSAECONNABORTED = 10053
		const WSAECONNRESET = 10054

		if oe, ok := err.(*net.OpError); ok {
			if oe.Op == "read" {
				if se, ok := oe.Err.(*os.SyscallError); ok {
					if se.Syscall == "wsarecv" {
						if n := erz(se.Err); n == WSAECONNRESET || n == WSAECONNABORTED {
							return true
						}
					}
				}
			}
		}

		return false
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ECONNRESET
	}
	return false
}

// IsConnectionRefused returns true if given err is a "connection refused" error
func IsConnectionRefused(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ECONNREFUSED
	}
	return false
}

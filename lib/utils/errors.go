/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package utils

import (
	"fmt"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var removePart atomic.Value

// DecorateError changes the error to something more comprehensible when
// timeout occured
func DecorateError(err error, action string, timeout time.Duration) error {
	if IsTimeout(err) {
		if timeout > 0 {
			return fmt.Errorf("%s took too long (> %v) to respond", action, timeout)
		}
		return fmt.Errorf("%s took too long to respond", action)
	}
	msg := err.Error()
	if strings.Index(msg, "desc = ") != -1 {
		pos := strings.Index(msg, "desc = ") + 7
		msg = msg[pos:]

		if strings.Index(msg, " :") == 0 {
			msg = msg[2:]
		}
		return errors.New(msg)
	}
	return err
}

// IsTimeout tells if the err is a timeout kind
func IsTimeout(err error) bool {
	return status.Code(err) == codes.DeadlineExceeded
}

// errCore ...
type errCore struct {
	message string
}

func (e errCore) Error() string {
	return e.message
}

// ErrTimeout defines a Timeout error
type ErrTimeout struct {
	errCore
}

// TimeoutError ...
func TimeoutError(msg string) ErrTimeout {
	return ErrTimeout{
		errCore: errCore{
			message: msg,
		},
	}
}

// ErrNotFound resource not found error
type ErrNotFound struct {
	errCore
}

// NotFoundError creates a ResourceNotFound error
func NotFoundError(msg string) ErrNotFound {
	return ErrNotFound{
		errCore: errCore{
			message: msg,
		},
	}
}

// ErrNotAvailable resource not available error
type ErrNotAvailable struct {
	errCore
}

// NotAvailableError creates a NotAvailable error
func NotAvailableError(msg string) ErrNotAvailable {
	return ErrNotAvailable{
		errCore: errCore{
			message: msg,
		},
	}
}

// ErrAlreadyExists resource already exists error
type ErrAlreadyExists struct {
	errCore
}

// AlreadyExistsError creates a ResourceAlreadyExists error
func AlreadyExistsError(msg string) ErrAlreadyExists {
	return ErrAlreadyExists{
		errCore: errCore{
			message: msg,
		},
	}
}

// ErrInvalidRequest ...
type ErrInvalidRequest struct {
	errCore
}

// InvalidRequestError creates a ErrInvalidRequest error
func InvalidRequestError(msg string) ErrInvalidRequest {
	return ErrInvalidRequest{
		errCore: errCore{
			message: msg,
		},
	}
}

// ErrAborted ...
type ErrAborted struct {
	errCore
}

// AbortedError creates a ErrAborted error
func AbortedError() ErrAborted {
	return ErrAborted{
		errCore: errCore{
			message: "aborted",
		},
	}
}

// ErrOverflow ...
type ErrOverflow struct {
	errCore
}

// OverflowError creates a ErrOverflow error
func OverflowError(msg string) ErrOverflow {
	return ErrOverflow{
		errCore: errCore{
			message: msg,
		},
	}
}

// ErrNotImplemented ...
type ErrNotImplemented struct {
	errCore
}

// NotImplementedError creates a ErrNotImplemented error
func NotImplementedError(what string) ErrNotImplemented {
	var msg string
	if pc, file, line, ok := runtime.Caller(1); ok {
		if f := runtime.FuncForPC(pc); f != nil {
			filename := strings.Replace(file, getPartToRemove(), "", 1)
			msg = fmt.Sprintf("not implemented yet: %s [%s:%d]", filepath.Base(f.Name()), filename, line)
		}
	}
	if msg == "" {
		msg = "not implemented yet!"
	}

	log.Error(Capitalize(msg))
	return ErrNotImplemented{
		errCore: errCore{
			message: msg,
		},
	}
}

// ErrInvalidInstance ...
type ErrInvalidInstance struct {
	errCore
}

// InvalidInstanceError creates a ErrInvalidInstance error
func InvalidInstanceError() ErrInvalidInstance {
	var msg string
	if pc, file, line, ok := runtime.Caller(2); ok {
		if f := runtime.FuncForPC(pc); f != nil {
			filename := strings.Replace(file, getPartToRemove(), "", 1)
			msg = fmt.Sprintf("invalid instance: calling %s() from a nil pointer [%s:%d]\n%s", filepath.Base(f.Name()), filename, line, debug.Stack())
		}
	}
	if msg == "" {
		msg = fmt.Sprintf("invalid instance: calling from a nil pointer")
	}

	log.Error(Capitalize(msg))
	return ErrInvalidInstance{
		errCore: errCore{
			message: msg,
		},
	}
}

// ErrInvalidParameter ...
type ErrInvalidParameter struct {
	errCore
}

// InvalidParameterError creates a ErrInvalidParameter error
func InvalidParameterError(what, why string) ErrInvalidParameter {
	var msg string
	if pc, file, line, ok := runtime.Caller(1); ok {
		if f := runtime.FuncForPC(pc); f != nil {
			filename := strings.Replace(file, getPartToRemove(), "", 1)
			msg = fmt.Sprintf("invalid parameter '%s' in %s: %s [%s:%d]\n%s", what, filepath.Base(f.Name()), why, filename, line, debug.Stack())
		}
	}
	if msg == "" {
		msg = fmt.Sprintf("nvalid parameter '%s': %s", what, why)
	}

	log.Error(Capitalize(msg))
	return ErrInvalidParameter{
		errCore: errCore{
			message: msg,
		},
	}
}

func getPartToRemove() string {
	if anon := removePart.Load(); anon != nil {
		return anon.(string)
	}
	return "github.com/CS-SI/SafeScale/"
}

func init() {
	var rootPath string
	if pc, _, _, ok := runtime.Caller(0); ok {
		if f := runtime.FuncForPC(pc); f != nil {
			rootPath = strings.Split(f.Name(), "lib/utils/")[0]
		}
	}
	removePart.Store(rootPath)
}

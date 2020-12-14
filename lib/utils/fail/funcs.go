/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package fail

import (
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
)

// AddConsequence adds an error 'err' to the list of consequences
func AddConsequence(err error, cons error) error {
	if err != nil {
		if conseq, ok := err.(consequencer); ok {
			if cons != nil {
				nerr := conseq.AddConsequence(cons)
				return nerr
			}
			return err
		}
		if cons != nil {
			logrus.Errorf("trying to add error [%s] to existing error [%s] but failed", cons, err)
		}
	}
	return err
}

// Consequences returns the list of consequences
func Consequences(err error) []error {
	if err != nil {
		if conseq, ok := err.(consequencer); ok {
			return conseq.Consequences()
		}
	}

	return []error{}
}

// Annotate ...
func Annotate(err error, key string, content interface{}) Error {
	if err != nil {
		enrich, ok := err.(Error)
		if !ok {
			enrich = NewError(err.Error())
		}
		if key != "" {
			_ = enrich.Annotate(key, content)
		}
		return enrich
	}
	return nil
}

// IsGRPCTimeout tells if the err is a ImplTimeout kind
func IsGRPCTimeout(err error) bool {
	return grpcstatus.Code(err) == codes.DeadlineExceeded
}

// IsGRPCError tells if the err is of GRPC kind
func IsGRPCError(err error) bool {
	if err == nil {
		return false
	}
	_, ok := grpcstatus.FromError(err)
	return ok
}

// FromGRPCStatus translates GRPC status to error
func FromGRPCStatus(err error) Error {
	if _, ok := err.(Error); ok {
		return err.(Error)
	}

	message := grpcstatus.Convert(err).Message()
	code := grpcstatus.Code(err)
	common := &errorCore{message: message, grpcCode: code}
	switch code {
	case codes.DeadlineExceeded:
		return &ErrTimeout{errorCore: common, dur: 0}
	case codes.Aborted:
		return &ErrAborted{common}
	case codes.FailedPrecondition:
		return &ErrInvalidParameter{common}
	case codes.AlreadyExists:
		return &ErrDuplicate{common}
	case codes.InvalidArgument:
		return &ErrInvalidRequest{common}
	case codes.NotFound:
		return &ErrNotFound{common}
	case codes.PermissionDenied:
		return &ErrForbidden{common}
	case codes.ResourceExhausted:
		return &ErrOverload{common}
	case codes.OutOfRange:
		return &ErrOverflow{errorCore: common, limit: 0}
	case codes.Unimplemented:
		return &ErrNotImplemented{common}
	case codes.Internal:
		return &ErrRuntimePanic{common}
	case codes.DataLoss:
		return &ErrInconsistent{common}
	case codes.Unauthenticated:
		return &ErrNotAuthenticated{common}
	}
	return common
}

// ToGRPCStatus translates an error to a GRPC status
func ToGRPCStatus(err error) error {
	if casted, ok := err.(Error); ok {
		return casted.ToGRPCStatus()
	}
	return grpcstatus.Errorf(codes.Unknown, err.Error())
}

// prependMessage prepends a message to an existing error, trying to keep error type when possible
func prependMessage(err error, msg ...interface{}) Error {
	switch rerr := err.(type) {
	case *errorCore:
		rerr.message = strprocess.FormatStrings(msg...) + ": " + rerr.message
		return err.(Error)
	default:
		return NewError("%s: %s", strprocess.FormatStrings(msg...), err.Error())
	}
}

// Wrap creates a new error with a message 'msg' and a causer error 'cause'
func Wrap(cause error, msg ...interface{}) Error {
	switch rerr := cause.(type) {
	case Error:
		rerr.prependToMessage(strprocess.FormatStrings(msg...))
		return rerr
	default:
		newErr := newError(cause, nil, msg...)
		// if cause != nil {
		// 	switch v := cause.(type) {
		// 	case Error:
		// 		newErr.grpcCode = v.GRPCCode()
		// 	}
		// }
		return newErr
	}
}

// RootCause returns the root cause of an error, or nil if there no root cause
func RootCause(err error) (resp error) {
	resp = err
	for err != nil {
		realErr, ok := err.(Error)
		if !ok {
			break
		}
		cause := realErr.Cause()
		if cause != nil {
			resp = cause
		}
		err = cause
	}
	return resp
}

// Cause returns the first immediate cause of an error, or nil if there no cause
func Cause(err error) (resp error) {
	resp = err
	core, ok := err.(Error)
	if ok {
		err = core.Cause()
		if err != nil {
			resp = err
		}
	}
	return resp
}

// ToError converts an error to a fail.Error
func ToError(err error) Error {
	if err != nil {
		if casted, ok := err.(Error); ok {
			return casted
		}
		return NewError(err.Error())
	}
	return nil
}

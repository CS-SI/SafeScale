/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
		conseq, ok := err.(Error)
		if ok {
			if cons != nil {
				nerr := conseq.AddConsequence(cons)
				return nerr
			}
			return conseq
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
		conseq, ok := err.(Error)
		if ok {
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
		return &ImplTimeout{errorCore: common, dur: 0}
	case codes.Aborted:
		return &ImplAborted{common}
	case codes.FailedPrecondition:
		return &ImplInvalidParameter{common}
	case codes.AlreadyExists:
		return &ImplDuplicate{common}
	case codes.InvalidArgument:
		return &ImplInvalidRequest{common}
	case codes.NotFound:
		return &ImplNotFound{common}
	case codes.PermissionDenied:
		return &ImplForbidden{common}
	case codes.ResourceExhausted:
		return &ImplOverload{common}
	case codes.OutOfRange:
		return &ImplOverflow{errorCore: common, limit: 0}
	case codes.Unimplemented:
		return &ImplNotImplemented{common}
	case codes.Internal:
		return &ImplRuntimePanic{common}
	case codes.DataLoss:
		return &ImplInconsistent{common}
	case codes.Unauthenticated:
		return &ImplNotAuthenticated{common}
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

// Wrap creates a new error with a message 'message' and a causer error 'causer'
func Wrap(cause error, msg ...interface{}) Error {
	// If the cause is already an Error, make sure we don't lose its real type during the operation
	if coreErr, ok := cause.(*errorCore); ok {
		coreErr.message = strprocess.FormatStrings(msg...) + ": " + coreErr.message
		return cause.(Error)
	}

	// classical error, create a new Error
	newErr := &errorCore{
		message:      strprocess.FormatStrings(msg...),
		causer:       cause,
		consequences: []error{},
		grpcCode:     codes.Unknown,
	}
	return newErr
}

// Cause returns the root cause of an error, or nil if there no root cause
func Cause(err error) (resp error) {
	resp = err

	for err != nil {
		cause, ok := err.(Error)
		if !ok {
			break
		}
		err = cause.Cause()
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

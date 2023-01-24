/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
)

// AddConsequence adds an error 'err' to the list of consequences
func AddConsequence(err error, cons error) error {
	if err != nil {
		if conseq, ok := err.(consequencer); ok {
			if cons != nil {
				convErr := Wrap(cons)
				nerr := conseq.AddConsequence(convErr)
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
			enrich.Annotate(key, content)
		}
		return enrich
	}
	return nil
}

// IsGRPCError tells if 'err' is of GRPC kind
func IsGRPCError(err error) bool {
	if err != nil {
		_, ok := grpcstatus.FromError(err)
		return ok
	}

	return false
}

// FromGRPCStatus translates GRPC status to error
func FromGRPCStatus(err error) Error {
	if err == nil {
		return InvalidParameterCannotBeNilError("err")
	}

	if _, ok := err.(Error); ok {
		return err.(Error)
	}

	message := grpcstatus.Convert(err).Message()
	code := grpcstatus.Code(err)
	common := newError(nil, nil, message)
	common.grpcCode = code
	switch code {
	case codes.DeadlineExceeded:
		return &ErrTimeout{errorCore: common, dur: 0}
	case codes.Aborted:
		return &ErrAborted{common}
	case codes.FailedPrecondition:
		return &ErrInvalidParameter{
			errorCore: common,
		}
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
	if err == nil {
		return InvalidParameterCannotBeNilError("err")
	}

	if casted, ok := err.(Error); ok {
		return casted.ToGRPCStatus()
	}

	return grpcstatus.Errorf(codes.Unknown, err.Error())
}

// Wrap creates a new error with a message 'msg' and a causer error 'cause'
func Wrap(cause error, msg ...interface{}) Error {
	if cause == nil {
		if len(msg) == 0 {
			return nil
		}
		return newError(nil, nil, msg...)
	}

	switch rerr := cause.(type) {
	case *ErrorList:
		return NewErrorListComplete(rerr.ToErrorSlice(), rerr.Cause(), rerr.Consequences(), msg...)
	case *ErrUnqualified:
		return newError(cause, rerr.Consequences(), msg...)
	case *ErrWarning:
		return WarningErrorWithCauseAndConsequences(cause, rerr.Consequences(), msg...)
	case *ErrTimeout:
		return TimeoutErrorWithCauseAndConsequences(cause, rerr.dur, rerr.Consequences(), msg...)
	case *ErrNotFound:
		return NotFoundErrorWithCause(cause, rerr.Consequences(), msg...)
	case *ErrAborted:
		return AbortedErrorWithCauseAndConsequences(cause, rerr.Consequences(), msg...)
	case *ErrRuntimePanic:
		var wrapArgs []interface{}
		wrapArgs = append(wrapArgs, rerr.UnformattedError())
		wrapArgs = append(wrapArgs, msg...)
		return RuntimePanicErrorWithCauseAndConsequences(cause, rerr.Consequences(), false, wrapArgs)
	case *ErrNotAvailable:
		return NotAvailableErrorWithCause(cause, rerr.Consequences(), msg...)
	case *ErrDuplicate:
		return DuplicateErrorWithCause(cause, rerr.Consequences(), msg...)
	case *ErrInvalidRequest:
		return InvalidRequestErrorWithCause(cause, rerr.Consequences(), msg...)
	case *ErrSyntax:
		return SyntaxErrorWithCause(cause, rerr.Consequences(), msg...)
	case *ErrNotAuthenticated:
		return NotAuthenticatedErrorWithCause(cause, rerr.Consequences(), msg...)
	case *ErrForbidden:
		return ForbiddenErrorWithCause(cause, rerr.Consequences(), msg...)
	case *ErrOverflow:
		return OverflowErrorWithCause(cause, rerr.limit, rerr.Consequences(), msg...)
	case *ErrOverload:
		return OverloadErrorWithCause(cause, rerr.Consequences(), msg...)
	case *ErrNotImplemented:
		return NotImplementedErrorWithCauseAndConsequences(cause, rerr.Consequences(), msg...)
	case *ErrInvalidInstance:
		return InvalidInstanceErrorWithCause(cause, rerr.Consequences(), msg...)
	case *ErrInvalidParameter:
		return InvalidParameterErrorWithCauseAndConsequences(cause, rerr.Consequences(), rerr.what, rerr.skip, msg...)
	case *ErrInvalidInstanceContent:
		return InvalidInstanceContentErrorWithCause(cause, rerr.Consequences(), rerr.what, rerr.why, msg...)
	case *ErrInconsistent:
		return InconsistentErrorWithCause(cause, rerr.Consequences(), msg...)
	case *ErrExecution:
		return ExecutionErrorWithCause(cause, rerr.Consequences(), msg...)
	case *ErrAlteredNothing:
		return AlteredNothingErrorWithCause(cause, rerr.Consequences(), msg...)
	case *ErrUnknown:
		return UnknownErrorWithCause(cause, rerr.Consequences(), msg...)
	case Error:
		return newError(cause, rerr.Consequences(), msg...)
	default:
		return newError(cause, nil, msg...)
	}
}

func lastUnwrapOrNil(in error) (err error) {
	if in == nil {
		return nil
	}

	last := in
	for {
		err = last
		u, ok := last.(interface {
			Unwrap() error
		})
		if !ok {
			break
		}
		last = u.Unwrap()
	}

	return err
}

func lastUnwrap(in error) (err error) {
	if in == nil {
		return nil
	}

	last := in
	for {
		err = last
		u, ok := last.(interface {
			Unwrap() error
		})
		if !ok {
			break
		}
		tmpLast := u.Unwrap()
		if tmpLast != nil {
			last = tmpLast
		} else {
			break
		}
	}

	return err
}

// RootCause follows the chain of causes / wrapped errors and returns the last not-nil error
func RootCause(err error) (resp error) {
	return lastUnwrap(err)
}

// Cause returns the direct cause of an error if it implements the causer interface and that cause is not-nil
// in any other case, returns the unmodified error 'err'
func Cause(err error) (resp error) {
	if ci, ok := err.(causer); ok {
		cau := ci.Cause()
		if cau != nil {
			return cau
		}

		return err
	}

	if u, ok := err.(interface {
		Unwrap() error
	}); ok {
		cau := u.Unwrap()
		if cau != nil {
			return cau
		}

		return err
	}

	return err
}

// // ConvertError converts an error to a fail.Error
// func ConvertError(err error) Error {
// 	if err != nil {
// 		if casted, ok := err.(Error); ok {
// 			return casted
// 		}
// 		return NewErrorWithCause(Cause(err), err.Error())
// 	}
// 	return nil
// }

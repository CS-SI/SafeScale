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
		conseq, ok := err.(Report)
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
		conseq, ok := err.(Report)
		if ok {
			return conseq.Consequences()
		}
	}

	return []error{}
}

// WithField ...
func WithField(err error, key string, content interface{}) Report {
	if err != nil {
		enrich, ok := err.(Report)
		if !ok {
			enrich = NewReport(err.Error())
		}
		if key != "" {
			return enrich.WithField(key, content)
		}
		return enrich
	}
	return nil
}

// // DecorateError changes the error to something more comprehensible when
// // timeout occurred
// func DecorateError(err error, action string, timeout time.Duration) error {
// 	if IsGRPCTimeout(err) {
// 		if timeout > 0 {
// 			return fmt.Errorf("%s took too long (> %v) to respond", action, timeout)
// 		}
// 		return fmt.Errorf("%s took too long to respond", action)
// 	}
// 	msg := err.Report()
// 	if strings.Contains(msg, "desc = ") {
// 		pos := strings.Index(msg, "desc = ") + 7
// 		msg = msg[pos:]

// 		if strings.Index(msg, " :") == 0 {
// 			msg = msg[2:]
// 		}
// 		return fmt.Errorf(msg)
// 	}
// 	return err
// }

// IsGRPCTimeout tells if the err is a timeout kind
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
func FromGRPCStatus(err error) Report {
	if _, ok := err.(Report); ok {
		return err.(Report)
	}

	message := grpcstatus.Convert(err).Message()
	code := grpcstatus.Code(err)
	common := &reportCore{message: message, grpcCode: code}
	switch code {
	case codes.DeadlineExceeded:
		return &timeout{reportCore: common}
	case codes.Aborted:
		return &aborted{reportCore: common}
	case codes.FailedPrecondition:
		return &invalidParameter{reportCore: common}
	case codes.AlreadyExists:
		return &duplicate{reportCore: common}
	case codes.InvalidArgument:
		return &invalidRequest{reportCore: common}
	case codes.NotFound:
		return &notFound{reportCore: common}
	case codes.PermissionDenied:
		return &forbidden{reportCore: common}
	case codes.ResourceExhausted:
		return &overload{reportCore: common}
	case codes.OutOfRange:
		return &overflow{reportCore: common}
	case codes.Unimplemented:
		return &notImplemented{reportCore: common}
	case codes.Internal:
		return &runtimePanic{reportCore: common}
	case codes.DataLoss:
		return &inconsistent{reportCore: common}
	case codes.Unauthenticated:
		return &notAuthenticated{reportCore: common}
	}
	return common
}

// ToGRPCStatus translates an error to a GRPC status
func ToGRPCStatus(err error) error {
	if casted, ok := err.(Report); ok {
		return casted.ToGRPCStatus()
	}
	return grpcstatus.Errorf(codes.Unknown, err.Error())
}

// Wrap creates a new error with a message 'message' and a causer error 'causer'
func Wrap(cause error, msg ...interface{}) Report {
	newErr := &reportCore{message: strprocess.FormatStrings(msg...), causer: cause, consequences: []error{}}
	if casted, ok := cause.(Report); ok {
		newErr.grpcCode = casted.GRPCCode()
	} else {
		newErr.grpcCode = codes.Unknown
	}
	return newErr
}

// Cause returns the causer of an error if it implements the causer interface
func Cause(err error) (resp error) {
	resp = err

	for err != nil {
		cause, ok := err.(Report)
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

// ErrorToReport converts an error to a fail.Report
func ErrorToReport(err error) Report {
	if err != nil {
		if casted, ok := err.(Report); ok {
			return casted
		}
		return NewReport(err.Error())
	}
	return nil
}

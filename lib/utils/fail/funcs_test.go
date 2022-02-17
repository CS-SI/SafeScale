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

package fail

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func Test_AddConsequence(t *testing.T) {

	err := AddConsequence(nil, nil)
	require.EqualValues(t, err, nil)

	err = AddConsequence(NotFoundError("Any message"), errors.New("not good type !"))
	require.EqualValues(t, strings.Contains(err.Error(), "Any message"), true)

	err = AddConsequence(errors.New("Any message"), errors.New("Consequence"))
	require.EqualValues(t, strings.Contains(err.Error(), "Any message"), true)

	err = AddConsequence(NotFoundError("Any message"), nil)
	require.EqualValues(t, strings.Contains(err.Error(), "Any message"), true)

	err = AddConsequence(NotFoundError("Any message 1"), NotFoundError("Any message 2"))
	require.EqualValues(t, strings.Contains(err.Error(), "Any message 2"), true)

}

func Test_Consequences(t *testing.T) {

	errs := Consequences(nil)
	require.EqualValues(t, len(errs), 0)

	errs = Consequences(errors.New("Any error"))
	require.EqualValues(t, len(errs), 0)

	err := &errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation"), errors.New("can't fins any result")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	errs = Consequences(err)
	require.EqualValues(t, len(errs), 2)

}

func Test_Annotate(t *testing.T) {

	v := struct {
		value string
		state bool
	}{"value", true}

	err := Annotate(nil, "key", v)
	require.EqualValues(t, err, nil)

	err = Annotate(errors.New("Any error"), "key", v)
	require.EqualValues(t, err.Annotations()["key"], v)

	err = Annotate(NotFoundError("Any message"), "key", v)
	require.EqualValues(t, err.Annotations()["key"], v)

	err = Annotate(NotFoundError("Any message"), "", v)
	if _, ok := err.Annotations()["key"]; ok {
		t.Fail()
	}

}

func Test_IsGRPCError(t *testing.T) {

	require.EqualValues(t, IsGRPCError(nil), false)

	err := grpcstatus.Error(codes.NotFound, "id was not found")
	require.EqualValues(t, IsGRPCError(err), true)

	errCore := &errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.DeadlineExceeded,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	require.EqualValues(t, IsGRPCError(errCore), false)

	xerr := &ErrWarning{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.DeadlineExceeded,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, IsGRPCError(xerr), false)

}

func Test_FromGRPCStatus(t *testing.T) {

	result := FromGRPCStatus(nil)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*fail.ErrInvalidParameter")

	err := grpcstatus.Error(codes.NotFound, "id was not found")
	result = FromGRPCStatus(err)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*fail.ErrNotFound")

	errCore := &errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.DeadlineExceeded,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = FromGRPCStatus(errCore)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*fail.errorCore")

	xerr := &ErrWarning{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.DeadlineExceeded,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = FromGRPCStatus(xerr)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*fail.ErrWarning")

	codes := map[codes.Code]string{
		codes.DeadlineExceeded:   "*fail.ErrTimeout",
		codes.Aborted:            "*fail.ErrAborted",
		codes.FailedPrecondition: "*fail.ErrInvalidParameter",
		codes.AlreadyExists:      "*fail.ErrDuplicate",
		codes.InvalidArgument:    "*fail.ErrInvalidRequest",
		codes.NotFound:           "*fail.ErrNotFound",
		codes.PermissionDenied:   "*fail.ErrForbidden",
		codes.ResourceExhausted:  "*fail.ErrOverload",
		codes.OutOfRange:         "*fail.ErrOverflow",
		codes.Unimplemented:      "*fail.ErrNotImplemented",
		codes.Internal:           "*fail.ErrRuntimePanic",
		codes.DataLoss:           "*fail.ErrInconsistent",
		codes.Unauthenticated:    "*fail.ErrNotAuthenticated",
	}
	for k, v := range codes {
		err = grpcstatus.Error(k, fmt.Sprintf("grpccode %d to %s", k, v))
		result = FromGRPCStatus(err)
		require.EqualValues(t, reflect.TypeOf(result).String(), v)
	}

}

func Test_ToGRPCStatus(t *testing.T) {

	result := ToGRPCStatus(nil)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*fail.ErrInvalidParameter")
	require.EqualValues(t, strings.Contains(result.Error(), "rpc error"), false)
	require.EqualValues(t, strings.Contains(result.Error(), "code = Unknown"), false)

	err := grpcstatus.Error(codes.NotFound, "id was not found")
	result = ToGRPCStatus(err)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*status.Error")
	require.EqualValues(t, strings.Contains(result.Error(), "rpc error"), true)
	require.EqualValues(t, strings.Contains(result.Error(), "code = Unknown"), true)
	require.EqualValues(t, strings.Contains(result.Error(), "desc = id was not found"), true)

	errCore := &errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.DeadlineExceeded,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = ToGRPCStatus(errCore)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*status.Error")
	require.EqualValues(t, strings.Contains(result.Error(), "rpc error"), true)
	require.EqualValues(t, strings.Contains(result.Error(), "code = DeadlineExceeded"), true)
	require.EqualValues(t, strings.Contains(result.Error(), "desc = houston, we have a problem"), true)

	xerr := &ErrWarning{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.DeadlineExceeded,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = ToGRPCStatus(xerr)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*status.Error")
	require.EqualValues(t, strings.Contains(result.Error(), "rpc error"), true)
	require.EqualValues(t, strings.Contains(result.Error(), "code = DeadlineExceeded"), true)
	require.EqualValues(t, strings.Contains(result.Error(), "desc = houston, we have a problem"), true)

	err = errors.New("any error")
	result = ToGRPCStatus(err)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*status.Error")
	require.EqualValues(t, strings.Contains(result.Error(), "rpc error"), true)
	require.EqualValues(t, strings.Contains(result.Error(), "code = Unknown"), true)
	require.EqualValues(t, strings.Contains(result.Error(), "desc = any error"), true)

}

func Test_Wrap(t *testing.T) {

	result := Wrap(nil, "any error")
	require.EqualValues(t, reflect.TypeOf(result).String(), "*fail.errorCore")
	require.EqualValues(t, result.Error(), "any error")

	errs := NewErrorList([]error{errors.New("math: square root of negative number"), errors.New("can't resolve equation")})
	result = Wrap(errs, "any error")
	require.EqualValues(t, reflect.TypeOf(result).String(), "*fail.ErrorList")
	require.EqualValues(t, strings.Contains(result.Error(), "square root of negative number"), true)
	require.EqualValues(t, strings.Contains(result.Error(), "can't resolve equation"), true)

}

func Test_lastUnwrapOrNil(t *testing.T) {

	result := lastUnwrapOrNil(nil)
	require.EqualValues(t, result, nil)

	err := errors.New("any error")
	result = lastUnwrapOrNil(err)
	require.EqualValues(t, strings.Contains(result.Error(), "any error"), true)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*errors.errorString")

	errs := NewErrorList([]error{errors.New("math: square root of negative number"), errors.New("can't resolve equation")})
	result = lastUnwrapOrNil(errs)
	require.EqualValues(t, result, nil)

}

func Test_lastUnwrap(t *testing.T) {

	result := lastUnwrap(nil)
	require.EqualValues(t, result, nil)

	err := errors.New("any error")
	result = lastUnwrap(err)
	require.EqualValues(t, strings.Contains(result.Error(), "any error"), true)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*errors.errorString")

	errs := NewErrorList([]error{errors.New("math: square root of negative number"), errors.New("can't resolve equation")})
	result = lastUnwrap(errs)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*fail.ErrorList")
	require.EqualValues(t, strings.Contains(result.Error(), "square root of negative number"), true)
	require.EqualValues(t, strings.Contains(result.Error(), "can't resolve equation"), true)

}

func Test_Cause(t *testing.T) {

	result := Cause(nil)
	require.EqualValues(t, result, nil)

	err := errors.New("any error")
	result = Cause(err)
	require.EqualValues(t, strings.Contains(result.Error(), "any error"), true)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*errors.errorString")

	errs := NewErrorList([]error{errors.New("math: square root of negative number"), errors.New("can't resolve equation")})
	result = Cause(errs)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*fail.ErrorList")
	require.EqualValues(t, strings.Contains(result.Error(), "square root of negative number"), true)
	require.EqualValues(t, strings.Contains(result.Error(), "can't resolve equation"), true)

	errCore := errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("error cause"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = Cause(&errCore)
	require.EqualValues(t, result.Error(), "error cause")
	require.EqualValues(t, reflect.TypeOf(result).String(), "*errors.errorString")

}

func Test_ConvertError(t *testing.T) {

	result := ConvertError(nil)
	require.EqualValues(t, result, nil)

	err := errors.New("any error")
	result = ConvertError(err)

	require.EqualValues(t, strings.Contains(result.Error(), "any error"), true)
	require.EqualValues(t, reflect.TypeOf(result).String(), "*fail.ErrUnqualified")

}

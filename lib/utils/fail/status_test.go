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

package fail

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

type junkErrorlike interface {
	error
	IsError()
}

type junkError struct {
	junkErrorlike
	message string
}

func (e *junkError) IsError() bool {
	return false
}

type IsErrorStatus struct {
	err     error
	isError bool
}

func Test_IsError(t *testing.T) {

	err := grpcstatus.Errorf(codes.Unknown, "Any error")
	result := IsError(err)
	require.EqualValues(t, result, true)

	err = &junkError{
		message: "any error",
	}
	result = IsError(err)
	require.EqualValues(t, result, false)

	tests := []IsErrorStatus{
		{
			err:     nil,
			isError: false,
		},
		{
			err:     errors.New("any error"),
			isError: true,
		},
		{
			err:     errors.New("any error"),
			isError: true,
		},
		{
			err: &errorCore{
				message:             "",
				cause:               nil,
				consequences:        []error{errors.New("can't resolve equation")},
				annotations:         make(data.Annotations),
				grpcCode:            codes.Unknown,
				causeFormatter:      nil,
				annotationFormatter: nil,
				lock:                &sync.RWMutex{},
			},
			isError: true,
		},
		{
			err: &ErrWarning{
				errorCore: &errorCore{
					message:             "houston, we have a problem",
					cause:               errors.New("math: can't divide by zero"),
					consequences:        []error{errors.New("can't resolve equation")},
					annotations:         make(data.Annotations),
					grpcCode:            codes.Unknown,
					causeFormatter:      defaultCauseFormatter,
					annotationFormatter: defaultAnnotationFormatter,
					lock:                &sync.RWMutex{},
				},
			},
			isError: true,
		},
		{
			err: &ErrTimeout{
				errorCore: &errorCore{
					message:             "houston, we have a problem",
					cause:               errors.New("math: can't divide by zero"),
					consequences:        []error{errors.New("can't resolve equation")},
					annotations:         make(data.Annotations),
					grpcCode:            codes.Unknown,
					causeFormatter:      defaultCauseFormatter,
					annotationFormatter: defaultAnnotationFormatter,
					lock:                &sync.RWMutex{},
				},
			},
			isError: true,
		},
		{
			err: &ErrNotFound{
				errorCore: &errorCore{
					message:             "houston, we have a problem",
					cause:               errors.New("math: can't divide by zero"),
					consequences:        []error{errors.New("can't resolve equation")},
					annotations:         make(data.Annotations),
					grpcCode:            codes.Unknown,
					causeFormatter:      defaultCauseFormatter,
					annotationFormatter: defaultAnnotationFormatter,
					lock:                &sync.RWMutex{},
				},
			},
			isError: true,
		},
	}

	for _, v := range tests {
		result := IsError(v.err)
		require.EqualValues(t, result, v.isError)
	}

}

func Test_StatusWrapErr(t *testing.T) {

	err := StatusWrapErr(errors.New("any error"), "message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.status")
	require.EqualValues(t, err.IsError(), true)
	require.EqualValues(t, err.Message(), "message")
	require.EqualValues(t, err.Cause().Error(), "any error")

}

func Test_Success(t *testing.T) {

	err := Success("message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.status")
	require.EqualValues(t, err.IsError(), false)
	require.EqualValues(t, err.Message(), "message")

}

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
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/json"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func Test_NewError(t *testing.T) {

	o := struct{}{}
	err := NewError(o)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrUnqualified")

}

func Test_NewErrorWithCause(t *testing.T) {

	o := struct{}{}
	err := NewErrorWithCause(errors.New("math: can't divide by zero"), o)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrUnqualified")
	require.NotEqual(t, strings.Index(err.Error(), "math: can't divide by zero"), -1)

}

func Test_NewErrorWithCauseAndConsequences(t *testing.T) {

	o := struct{}{}
	err := NewErrorWithCauseAndConsequences(errors.New("math: can't divide by zero"), []error{errors.New("can't resolve equation")}, o)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrUnqualified")
	require.NotEqual(t, strings.Index(err.Error(), "math: can't divide by zero"), -1)
	require.NotEqual(t, strings.Index(err.Error(), "can't resolve equation"), -1)

}

func Test_newError(t *testing.T) {

	o := "Something happens"
	err := newError(errors.New("math: can't divide by zero"), []error{errors.New("can't resolve equation")}, o)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.errorCore")
	require.EqualValues(t, err.message, "Something happens")
	require.EqualValues(t, err.cause.Error(), "math: can't divide by zero")
	require.EqualValues(t, err.consequences[0].Error(), "can't resolve equation")

}

func TestErrorCore_IsNull(t *testing.T) {

	var err *errorCore = nil
	require.EqualValues(t, err.IsNull(), true)
	err = &errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil,
	}
	require.EqualValues(t, err.IsNull(), true)
	err = &errorCore{
		message:             "",
		cause:               nil,
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      nil,
		annotationFormatter: nil,
		lock:                &sync.RWMutex{},
	}
	require.EqualValues(t, err.IsNull(), true)
	err = &errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func Test_defaultCauseFormatter(t *testing.T) {

	result := defaultCauseFormatter(nil)
	require.EqualValues(t, result, "")

	broken := &ErrUnqualified{
		errorCore: nil,
	}
	result = defaultCauseFormatter(broken)
	require.EqualValues(t, result, "")

	err := &errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation"), nil}, // partial invalid
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = defaultCauseFormatter(err)
	require.NotEqual(t, result, "")

	err = &errorCore{
		message:             "math: can't divide by zero",
		cause:               UnknownError("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = defaultCauseFormatter(err)
	require.NotEqual(t, result, "")

	err = &errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{UnknownError("consq 1"), UnknownError("consq 2"), UnknownError("consq 3")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = defaultCauseFormatter(err)
	require.NotEqual(t, result, "")

	err = &errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err.lock.Lock() // Huhu makes a deadlock ?
	result = defaultCauseFormatter(err)
	require.EqualValues(t, result, "")

	err = &errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = defaultCauseFormatter(err)
	require.NotEqual(t, result, "")

}

func TestErrorCore_CauseFormatter(t *testing.T) {

	defer func() {
		if r := recover(); r != nil {
			t.Error("Unexpected panic", r)
			t.Fail()
		}
	}()

	var err *errorCore = nil
	err.CauseFormatter(func(e Error) string {
		return e.Error()
	})

	err = &errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err.CauseFormatter(nil)

	// @TODO: Makes infiniteloop not possible here
	/*
		err = &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		}
		err.CauseFormatter(func(e Error) string {
			return fmt.Sprintf("MyWonderCause: %s", e.Error()) // <- makes infinite loop when parent call .Error(), quite fun -__-
		})
		_ = err.Error()
	*/

	err = &errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err.CauseFormatter(func(e Error) string {
		errCore, ok := e.(*errorCore)
		if !ok {
			return ""
		}
		return fmt.Sprintf(" because MyWonderCause is : %s", errCore.message)
	})
	result := err.Error()
	require.NotEqual(t, strings.Index(result, "MyWonderCause"), -1)

}

func TestErrorCore_Unwrap(t *testing.T) {

	errCore := errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil, //&sync.RWMutex{},
	}
	err := errCore.Unwrap()
	require.EqualValues(t, err.Error(), "")

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err = errCore.Unwrap()
	require.EqualValues(t, err.Error(), "math: can't divide by zero")

}

func TestErrorCore_Cause(t *testing.T) {

	errCore := errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil, //&sync.RWMutex{},
	}
	err := errCore.Cause()
	require.EqualValues(t, err.Error(), "")

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               nil,
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err = errCore.Cause()
	require.EqualValues(t, err, nil)

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err = errCore.Cause()
	require.EqualValues(t, err.Error(), "math: can't divide by zero")

}

func TestErrorCore_RootCause(t *testing.T) {

	defer func() {
		if r := recover(); r != nil {
			t.Error("Unexpected panic", r)
			t.Fail()
		}
	}()

	var err *errorCore = nil
	result := err.RootCause()

	err = &errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = err.RootCause()
	require.EqualValues(t, result.Error(), "math: can't divide by zero")

}

func Test_defaultAnnotationFormatter(t *testing.T) {

	var a data.Annotations = nil
	result := defaultAnnotationFormatter(a)
	require.EqualValues(t, result, "")

	a = data.Annotations{
		"test1": 42,
		"test2": "test",
		"test3": 43.92,
		"test4": false,
		"test5": func(a string) string { return a }, // No json.stringify, makes marshall fail
	}
	result = defaultAnnotationFormatter(a)
	require.EqualValues(t, result, "")

	a = data.Annotations{
		"test1": 42,
		"test2": "test",
		"test3": 43.92,
		"test4": false,
	}
	result = defaultAnnotationFormatter(a)
	require.EqualValues(t, result, "{\"test1\":42,\"test2\":\"test\",\"test3\":43.92,\"test4\":false}")

}

func TestErrorCore_Annotations(t *testing.T) {

	errCore := errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil, //&sync.RWMutex{},
	}
	ann := errCore.Annotations()
	require.EqualValues(t, len(ann), 0)

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         nil,
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	ann = errCore.Annotations()
	require.EqualValues(t, len(ann), 0)

	errCore = errorCore{
		message:      "math: can't divide by zero",
		cause:        errors.New("math: can't divide by zero"),
		consequences: []error{errors.New("can't resolve equation")},
		annotations: data.Annotations{
			"one":   "first",
			"two":   "second",
			"three": "thrid",
		},
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	ann = errCore.Annotations()
	require.EqualValues(t, len(ann), 3)

}

func TestErrorCore_Annotation(t *testing.T) {

	errCore := errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil, //&sync.RWMutex{},
	}
	ann, ok := errCore.Annotation("two")
	require.EqualValues(t, ok, false)

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         nil,
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	ann, ok = errCore.Annotation("two")
	require.EqualValues(t, ok, false)

	errCore = errorCore{
		message:      "math: can't divide by zero",
		cause:        errors.New("math: can't divide by zero"),
		consequences: []error{errors.New("can't resolve equation")},
		annotations: data.Annotations{
			"one":   "first",
			"two":   "second",
			"three": "thrid",
		},
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	ann, ok = errCore.Annotation("two")
	require.EqualValues(t, ok, true)
	require.EqualValues(t, ann, "second")

}

func TestErrorCore_Annotate(t *testing.T) {

	errCore := errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil, //&sync.RWMutex{},

	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := errCore.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         nil,
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = errCore.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrorCore_SetAnnotationFormatter(t *testing.T) {

	errCore := errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil, //&sync.RWMutex{},
	}
	errCore.SetAnnotationFormatter(func(anns data.Annotations) string {
		return "any"
	})

	errCore = errorCore{
		message:      "math: can't divide by zero",
		cause:        errors.New("math: can't divide by zero"),
		consequences: []error{errors.New("can't resolve equation")},
		annotations: map[string]interface{}{
			"two": "second one",
			"eggs": struct {
				source string
				price  float64
			}{"chicken", 1.75},
		},
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	errCore.SetAnnotationFormatter(nil)
	require.NotEqual(t, strings.Index(errCore.UnformattedError(), "{\"eggs\":{},\"two\":\"second one\"}"), -1)

	errCore.SetAnnotationFormatter(func(anns data.Annotations) string {
		if anns == nil {
			return ""
		}
		j, err := json.Marshal(anns)
		if err != nil {
			return ""
		}
		return string(j)
	})
	require.NotEqual(t, strings.Index(errCore.UnformattedError(), "{\"eggs\":{},\"two\":\"second one\"}"), -1)

}

func TestErrorCore_AddConsequence(t *testing.T) {

	errCore := errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil, //&sync.RWMutex{},

	}
	err := errCore.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err = errCore.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        nil,
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	_ = errCore.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(errCore.Consequences()).Error(), "current compute abort"), -1)

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	_ = errCore.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(errCore.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrorCore_Consequences(t *testing.T) {

	errCore := errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil, //&sync.RWMutex{},

	}
	cqs := errCore.Consequences()
	require.EqualValues(t, len(cqs), 0)

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	cqs = errCore.Consequences()
	require.NotEqual(t, strings.Index(NewErrorList(cqs).Error(), "can't resolve equation"), -1)

}

func TestErrorCore_Error(t *testing.T) {

	errCore := errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil, //&sync.RWMutex{},
	}
	result := errCore.Error()
	require.EqualValues(t, result, "")

	errCore = errorCore{
		message:      "math: can't divide by zero",
		cause:        errors.New("math: can't divide by zero"),
		consequences: []error{errors.New("can't resolve equation")},
		annotations: data.Annotations{
			"note1": struct{}{},
			"note2": struct{}{},
		},
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = errCore.Error()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = errCore.Error()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrorCore_UnformattedError(t *testing.T) {

	errCore := errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil, //&sync.RWMutex{},
	}
	result := errCore.UnformattedError()
	require.EqualValues(t, result, "")

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = errCore.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrorCore_GRPCCode(t *testing.T) {

	errCore := errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil, //&sync.RWMutex{},
	}
	result := errCore.GRPCCode()
	require.EqualValues(t, result, codes.Unknown)

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.OK,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = errCore.GRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func TestErrorCore_ToGRPCStatus(t *testing.T) {

	errCore := errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil, //&sync.RWMutex{},
	}
	err := errCore.ToGRPCStatus()
	require.EqualValues(t, err.Error(), "rpc error: code = Unknown desc = ")

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.OK,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err = errCore.ToGRPCStatus()
	require.EqualValues(t, err, nil)

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Canceled,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err = errCore.ToGRPCStatus()
	require.NotEqual(t, strings.Index(err.Error(), "Canceled"), -1)

}

func TestErrorCore_Prepend(t *testing.T) {

	errCore := errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                nil, //&sync.RWMutex{},
	}
	errCore.prependToMessage("Prefix")
	require.EqualValues(t, strings.Index(errCore.Error(), "Prefix"), -1)

	errCore = errorCore{
		message:             "math: can't divide by zero",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.OK,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	errCore.prependToMessage("Prefix: ")
	require.NotEqual(t, strings.Index(errCore.Error(), "Prefix"), -1)

}

func Test_WarningError(t *testing.T) {

	err := WarningError(errors.New("math: can't divide by zero"), "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrWarning")

}

func TestErrWarning_IsNull(t *testing.T) {

	var err *ErrWarning = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrWarning{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrWarning{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrWarning_AddConsequence(t *testing.T) {

	warning := &ErrWarning{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := warning.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	warning = &ErrWarning{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = warning.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	warning = &ErrWarning{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = warning.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(warning.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrWarning_Annotate(t *testing.T) {

	warning := &ErrWarning{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := warning.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	warning = &ErrWarning{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = warning.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)
}

func TestErrWarning_UnformattedError(t *testing.T) {

	warning := &ErrWarning{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := warning.UnformattedError()
	require.EqualValues(t, result, "")

	warning = &ErrWarning{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = warning.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func Test_TimeoutError(t *testing.T) {

	err := TimeoutError(errors.New("math: can't divide by zero"), 30*time.Second, "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrTimeout")

}

func TestErrTimeout_IsNull(t *testing.T) {

	var err *ErrTimeout = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrTimeout{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrTimeout{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrTimeout_AddConsequence(t *testing.T) {

	timeout := &ErrTimeout{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := timeout.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	timeout = &ErrTimeout{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = timeout.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	timeout = &ErrTimeout{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = timeout.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(timeout.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrTimeout_Annotate(t *testing.T) {

	timeout := &ErrTimeout{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := timeout.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	timeout = &ErrTimeout{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = timeout.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)
}

func TestErrTimeout_UnformattedError(t *testing.T) {

	timeout := &ErrTimeout{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := timeout.UnformattedError()
	require.EqualValues(t, result, "")

	timeout = &ErrTimeout{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = timeout.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func Test_ErrNotFound(t *testing.T) {

	err := NotFoundError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotFound")

}

func Test_NotFoundErrorWithCause(t *testing.T) {

	err := NotFoundErrorWithCause(errors.New("math: can't divide by zero"), "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotFound")

}

func TestErrNotFound_AddConsequence(t *testing.T) {

	notfound := &ErrNotFound{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := notfound.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	notfound = &ErrNotFound{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = notfound.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	notfound = &ErrNotFound{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = notfound.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(notfound.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrNotFound_Annotate(t *testing.T) {
	notfound := &ErrNotFound{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := notfound.Annotate("two", ann)

	notfound = &ErrNotFound{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = notfound.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrNotFound_UnformattedError(t *testing.T) {

	notfound := &ErrNotFound{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := notfound.UnformattedError()
	require.EqualValues(t, result, "")

	notfound = &ErrNotFound{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = notfound.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func Test_ErrNotAvailable(t *testing.T) {

	err := NotAvailableError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotAvailable")

}
func Test_NotAvailableErrorWithCause(t *testing.T) {

	err := NotAvailableErrorWithCause(errors.New("math: can't divide by zero"), "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotAvailable")

}

func TestErrNotAvailable_IsNull(t *testing.T) {

	var err *ErrNotAvailable = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrNotAvailable{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrNotAvailable{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrNotAvailable_AddConsequence(t *testing.T) {

	notavailable := &ErrNotAvailable{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := notavailable.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	notavailable = &ErrNotAvailable{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = notavailable.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	notavailable = &ErrNotAvailable{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = notavailable.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(notavailable.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrNotAvailable_Annotate(t *testing.T) {
	notavailable := &ErrNotAvailable{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := notavailable.Annotate("two", ann)

	notavailable = &ErrNotAvailable{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = notavailable.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrNotAvailable_UnformattedError(t *testing.T) {

	notavailable := &ErrNotAvailable{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := notavailable.UnformattedError()
	require.EqualValues(t, result, "")

	notavailable = &ErrNotAvailable{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = notavailable.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func Test_DuplicateError(t *testing.T) {

	err := DuplicateError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrDuplicate")

}
func Test_DuplicateErrorWithCause(t *testing.T) {

	err := DuplicateErrorWithCause(errors.New("math: can't divide by zero"), "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrDuplicate")

}

func TestDuplicateError_IsNull(t *testing.T) {

	var err *ErrDuplicate = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrDuplicate{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrDuplicate{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrDuplicate_AddConsequence(t *testing.T) {

	duplicateerr := &ErrDuplicate{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := duplicateerr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	duplicateerr = &ErrDuplicate{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = duplicateerr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	duplicateerr = &ErrDuplicate{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = duplicateerr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(duplicateerr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrDuplicate_UnformattedError(t *testing.T) {

	duplicateerr := &ErrDuplicate{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := duplicateerr.UnformattedError()
	require.EqualValues(t, result, "")

	duplicateerr = &ErrDuplicate{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = duplicateerr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrDuplicate_Annotate(t *testing.T) {
	duplicateerr := &ErrDuplicate{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := duplicateerr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	duplicateerr = &ErrDuplicate{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = duplicateerr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_InvalidRequestError(t *testing.T) {

	err := InvalidRequestError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidRequest")

}

func TestErrInvalidRequest_IsNull(t *testing.T) {

	var err *ErrInvalidRequest = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrInvalidRequest{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrInvalidRequest{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrInvalidRequest_AddConsequence(t *testing.T) {

	invalidreqerr := &ErrInvalidRequest{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := invalidreqerr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	invalidreqerr = &ErrInvalidRequest{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = invalidreqerr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	invalidreqerr = &ErrInvalidRequest{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = invalidreqerr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(invalidreqerr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrInvalidRequest_UnformattedError(t *testing.T) {

	invalidreqerr := &ErrInvalidRequest{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := invalidreqerr.UnformattedError()
	require.EqualValues(t, result, "")

	invalidreqerr = &ErrInvalidRequest{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = invalidreqerr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrInvalidRequest_Annotate(t *testing.T) {
	invalidreqerr := &ErrInvalidRequest{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := invalidreqerr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	invalidreqerr = &ErrInvalidRequest{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = invalidreqerr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_SyntaxError(t *testing.T) {

	err := SyntaxError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrSyntax")

}

func Test_SyntaxErrorWithCause(t *testing.T) {

	err := SyntaxErrorWithCause(errors.New("math: can't divide by zero"), "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrSyntax")

}

func TestErrSyntax_IsNull(t *testing.T) {

	var err *ErrSyntax = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrSyntax{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrSyntax{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrSyntax_AddConsequence(t *testing.T) {

	syntaxerr := &ErrSyntax{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := syntaxerr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	syntaxerr = &ErrSyntax{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = syntaxerr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	syntaxerr = &ErrSyntax{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = syntaxerr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(syntaxerr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrSyntax_UnformattedError(t *testing.T) {

	syntaxerr := &ErrSyntax{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := syntaxerr.UnformattedError()
	require.EqualValues(t, result, "")

	syntaxerr = &ErrSyntax{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = syntaxerr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrSyntax_Annotate(t *testing.T) {
	syntaxerr := &ErrSyntax{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := syntaxerr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	syntaxerr = &ErrSyntax{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = syntaxerr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_NotAuthenticatedError(t *testing.T) {

	err := NotAuthenticatedError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotAuthenticated")

}

func TestErrNotAuthenticated_IsNull(t *testing.T) {

	var err *ErrNotAuthenticated = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrNotAuthenticated{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrNotAuthenticated{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrNotAuthenticated_AddConsequence(t *testing.T) {

	autherr := &ErrNotAuthenticated{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := autherr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	autherr = &ErrNotAuthenticated{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = autherr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	autherr = &ErrNotAuthenticated{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = autherr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(autherr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrNotAuthenticated_UnformattedError(t *testing.T) {

	autherr := &ErrNotAuthenticated{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := autherr.UnformattedError()
	require.EqualValues(t, result, "")

	autherr = &ErrNotAuthenticated{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = autherr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrNotAuthenticated_Annotate(t *testing.T) {
	autherr := &ErrNotAuthenticated{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := autherr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	autherr = &ErrNotAuthenticated{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = autherr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_ForbiddenError(t *testing.T) {

	err := ForbiddenError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrForbidden")

}

func TestErrForbidden_IsNull(t *testing.T) {

	var err *ErrForbidden = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrForbidden{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrForbidden{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrForbidden_AddConsequence(t *testing.T) {

	forbiderr := &ErrForbidden{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := forbiderr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	forbiderr = &ErrForbidden{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = forbiderr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	forbiderr = &ErrForbidden{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = forbiderr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(forbiderr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrForbidden_UnformattedError(t *testing.T) {

	forbiderr := &ErrForbidden{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := forbiderr.UnformattedError()
	require.EqualValues(t, result, "")

	forbiderr = &ErrForbidden{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = forbiderr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrForbidden_Annotate(t *testing.T) {
	forbiderr := &ErrForbidden{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := forbiderr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	forbiderr = &ErrForbidden{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = forbiderr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_AbortedError(t *testing.T) {

	err := AbortedError(errors.New("math: can't divide by zero"), "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrAborted")

}

func TestErrAborted_IsNull(t *testing.T) {

	var err *ErrAborted = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrAborted{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrAborted{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrAborted_AddConsequence(t *testing.T) {

	aborterr := &ErrAborted{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := aborterr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	aborterr = &ErrAborted{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = aborterr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	aborterr = &ErrAborted{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = aborterr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(aborterr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrAborted_UnformattedError(t *testing.T) {

	aborterr := &ErrAborted{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := aborterr.UnformattedError()
	require.EqualValues(t, result, "")

	aborterr = &ErrAborted{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = aborterr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrAborted_Annotate(t *testing.T) {
	aborterr := &ErrAborted{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := aborterr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	aborterr = &ErrAborted{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = aborterr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_OverflowError(t *testing.T) {

	err := OverflowError(errors.New("math: can't divide by zero"), 30, "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrOverflow")

}

func TestErrOverflow_IsNull(t *testing.T) {

	var err *ErrOverflow = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrOverflow{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrOverflow{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrOverflow_AddConsequence(t *testing.T) {

	ovflowterr := &ErrOverflow{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := ovflowterr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	ovflowterr = &ErrOverflow{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = ovflowterr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	ovflowterr = &ErrOverflow{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = ovflowterr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(ovflowterr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrOverflow_UnformattedError(t *testing.T) {

	ovflowterr := &ErrOverflow{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := ovflowterr.UnformattedError()
	require.EqualValues(t, result, "")

	ovflowterr = &ErrOverflow{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = ovflowterr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrOverflow_Annotate(t *testing.T) {
	ovflowterr := &ErrOverflow{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := ovflowterr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	ovflowterr = &ErrOverflow{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = ovflowterr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_OverloadError(t *testing.T) {

	err := OverloadError("any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrOverload")

}

func TestErrOverload_IsNull(t *testing.T) {

	var err *ErrOverload = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrOverload{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrOverload{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrOverload_AddConsequence(t *testing.T) {

	overloadErr := &ErrOverload{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := overloadErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	overloadErr = &ErrOverload{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = overloadErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	overloadErr = &ErrOverload{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = overloadErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(overloadErr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrOverload_UnformattedError(t *testing.T) {

	overloadErr := &ErrOverload{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := overloadErr.UnformattedError()
	require.EqualValues(t, result, "")

	overloadErr = &ErrOverload{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = overloadErr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrOverload_Annotate(t *testing.T) {
	overloadErr := &ErrOverload{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := overloadErr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	overloadErr = &ErrOverload{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = overloadErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_NotImplementedError(t *testing.T) {

	err := NotImplementedError("any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotImplemented")

}

func Test_NotImplementedErrorWithReason(t *testing.T) {

	err := NotImplementedErrorWithReason("any error", "cause")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotImplemented")

}

func TestErrNotImplemented_IsNull(t *testing.T) {

	var err *ErrNotImplemented = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrNotImplemented{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrNotImplemented{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrNotImplemented_AddConsequence(t *testing.T) {

	notImplementedErr := &ErrNotImplemented{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := notImplementedErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	notImplementedErr = &ErrNotImplemented{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = notImplementedErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	notImplementedErr = &ErrNotImplemented{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = notImplementedErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(notImplementedErr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrNotImplemented_UnformattedError(t *testing.T) {

	notImplementedErr := &ErrNotImplemented{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := notImplementedErr.UnformattedError()
	require.EqualValues(t, result, "")

	notImplementedErr = &ErrNotImplemented{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = notImplementedErr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrNotImplemented_Annotate(t *testing.T) {
	notImplementedErr := &ErrNotImplemented{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := notImplementedErr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	notImplementedErr = &ErrNotImplemented{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = notImplementedErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_RuntimePanicError(t *testing.T) {

	err := RuntimePanicError("pattern %s", "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrRuntimePanic")

}

func TestErrRuntimePanic_IsNull(t *testing.T) {

	var err *ErrRuntimePanic = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrRuntimePanic{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrRuntimePanic{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrRuntimePanic_AddConsequence(t *testing.T) {

	notImplementedErr := &ErrRuntimePanic{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := notImplementedErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	notImplementedErr = &ErrRuntimePanic{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = notImplementedErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	notImplementedErr = &ErrRuntimePanic{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = notImplementedErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(notImplementedErr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrRuntimePanic_UnformattedError(t *testing.T) {

	notImplementedErr := &ErrRuntimePanic{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := notImplementedErr.UnformattedError()
	require.EqualValues(t, result, "")

	notImplementedErr = &ErrRuntimePanic{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = notImplementedErr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrRuntimePanic_Annotate(t *testing.T) {
	notImplementedErr := &ErrRuntimePanic{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := notImplementedErr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	notImplementedErr = &ErrRuntimePanic{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = notImplementedErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_InvalidInstanceError(t *testing.T) {

	err := InvalidInstanceError()
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstance")

}

func TestErrInvalidInstance_IsNull(t *testing.T) {

	var err *ErrInvalidInstance = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrInvalidInstance{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrInvalidInstance{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrInvalidInstance_AddConsequence(t *testing.T) {

	invalidInstanceErr := &ErrInvalidInstance{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := invalidInstanceErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	invalidInstanceErr = &ErrInvalidInstance{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = invalidInstanceErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	invalidInstanceErr = &ErrInvalidInstance{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = invalidInstanceErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(invalidInstanceErr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrInvalidInstance_UnformattedError(t *testing.T) {

	invalidInstanceErr := &ErrInvalidInstance{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := invalidInstanceErr.UnformattedError()
	require.EqualValues(t, result, "")

	invalidInstanceErr = &ErrInvalidInstance{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = invalidInstanceErr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrInvalidInstance_Annotate(t *testing.T) {
	invalidInstanceErr := &ErrInvalidInstance{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := invalidInstanceErr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	invalidInstanceErr = &ErrInvalidInstance{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = invalidInstanceErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_InvalidParameterError(t *testing.T) {

	err := InvalidParameterError("what is it", "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")

}

func Test_InvalidParameterCannotBeNilError(t *testing.T) {

	err := InvalidParameterCannotBeNilError("what is it")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")

}

func Test_InvalidParameterCannotBeEmptyStringError(t *testing.T) {

	err := InvalidParameterCannotBeEmptyStringError("what is it")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")

}

func TestErrInvalidParameter_IsNull(t *testing.T) {

	var err *ErrInvalidParameter = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrInvalidParameter{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrInvalidParameter{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrInvalidParameter_AddConsequence(t *testing.T) {

	invalidInstanceErr := &ErrInvalidParameter{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := invalidInstanceErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	invalidInstanceErr = &ErrInvalidParameter{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = invalidInstanceErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	invalidInstanceErr = &ErrInvalidParameter{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = invalidInstanceErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(invalidInstanceErr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrInvalidParameter_UnformattedError(t *testing.T) {

	invalidInstanceErr := &ErrInvalidParameter{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := invalidInstanceErr.UnformattedError()
	require.EqualValues(t, result, "")

	invalidInstanceErr = &ErrInvalidParameter{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = invalidInstanceErr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrInvalidParameter_Annotate(t *testing.T) {
	invalidInstanceErr := &ErrInvalidParameter{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := invalidInstanceErr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	invalidInstanceErr = &ErrInvalidParameter{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = invalidInstanceErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_InvalidInstanceContentError(t *testing.T) {

	err := InvalidInstanceContentError("what is it", "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstanceContent")

}

func TestErrInvalidInstanceContent_IsNull(t *testing.T) {

	var err *ErrInvalidInstanceContent = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrInvalidInstanceContent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrInvalidInstanceContent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrInvalidInstanceContent_AddConsequence(t *testing.T) {

	InvalidInstanceContentErr := &ErrInvalidInstanceContent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := InvalidInstanceContentErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	InvalidInstanceContentErr = &ErrInvalidInstanceContent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = InvalidInstanceContentErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	InvalidInstanceContentErr = &ErrInvalidInstanceContent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = InvalidInstanceContentErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(InvalidInstanceContentErr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrInvalidInstanceContent_UnformattedError(t *testing.T) {

	InvalidInstanceContentErr := &ErrInvalidInstanceContent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := InvalidInstanceContentErr.UnformattedError()
	require.EqualValues(t, result, "")

	InvalidInstanceContentErr = &ErrInvalidInstanceContent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = InvalidInstanceContentErr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrInvalidInstanceContent_Annotate(t *testing.T) {
	InvalidInstanceContentErr := &ErrInvalidInstanceContent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := InvalidInstanceContentErr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	InvalidInstanceContentErr = &ErrInvalidInstanceContent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = InvalidInstanceContentErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_InconsistentError(t *testing.T) {

	err := InconsistentError("any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInconsistent")

}

func TestErrInconsistent_IsNull(t *testing.T) {

	var err *ErrInconsistent = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrInconsistent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrInconsistent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrInconsistent_AddConsequence(t *testing.T) {

	inconsistentErr := &ErrInconsistent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := inconsistentErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	inconsistentErr = &ErrInconsistent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = inconsistentErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	inconsistentErr = &ErrInconsistent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = inconsistentErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(inconsistentErr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrInconsistent_UnformattedError(t *testing.T) {

	inconsistentErr := &ErrInconsistent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := inconsistentErr.UnformattedError()
	require.EqualValues(t, result, "")

	inconsistentErr = &ErrInconsistent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = inconsistentErr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrInconsistent_Annotate(t *testing.T) {
	inconsistentErr := &ErrInconsistent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := inconsistentErr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	inconsistentErr = &ErrInconsistent{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = inconsistentErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_ExecutionError(t *testing.T) {

	err := ExecutionError(errors.New("exit error"), "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrExecution")

}

func TestErrExecution_IsNull(t *testing.T) {

	var err *ErrExecution = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrExecution{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrExecution{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrExecution_AddConsequence(t *testing.T) {

	executionErr := &ErrExecution{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := executionErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	executionErr = &ErrExecution{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = executionErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	executionErr = &ErrExecution{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = executionErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(executionErr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrExecution_UnformattedError(t *testing.T) {

	executionErr := &ErrExecution{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := executionErr.UnformattedError()
	require.EqualValues(t, result, "")

	executionErr = &ErrExecution{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = executionErr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrExecution_Annotate(t *testing.T) {
	executionErr := &ErrExecution{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := executionErr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	executionErr = &ErrExecution{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = executionErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_AlteredNothingError(t *testing.T) {

	err := AlteredNothingError("any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrAlteredNothing")

}

func TestErrAlteredNothing_IsNull(t *testing.T) {

	var err *ErrAlteredNothing = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrAlteredNothing{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrAlteredNothing{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrAlteredNothing_AddConsequence(t *testing.T) {

	alteredNilErr := &ErrAlteredNothing{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := alteredNilErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	alteredNilErr = &ErrAlteredNothing{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = alteredNilErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	alteredNilErr = &ErrAlteredNothing{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = alteredNilErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(alteredNilErr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrAlteredNothing_UnformattedError(t *testing.T) {

	alteredNilErr := &ErrAlteredNothing{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := alteredNilErr.UnformattedError()
	require.EqualValues(t, result, "")

	alteredNilErr = &ErrAlteredNothing{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = alteredNilErr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrAlteredNothing_Annotate(t *testing.T) {
	alteredNilErr := &ErrAlteredNothing{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := alteredNilErr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	alteredNilErr = &ErrAlteredNothing{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = alteredNilErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func Test_UnknownError(t *testing.T) {

	err := UnknownError("any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrUnknown")

}

func TestErrUnknown_IsNull(t *testing.T) {

	var err *ErrUnknown = nil
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrUnknown{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), true)

	err = &ErrUnknown{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	require.EqualValues(t, err.IsNull(), false)

}

func TestErrUnknown_AddConsequence(t *testing.T) {

	unknownErr := &ErrUnknown{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}

	err := unknownErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	unknownErr = &ErrUnknown{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	err = unknownErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	unknownErr = &ErrUnknown{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	_ = unknownErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(unknownErr.Consequences()).Error(), "current compute abort"), -1)

}

func TestErrUnknown_UnformattedError(t *testing.T) {

	unknownErr := &ErrUnknown{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},
		},
	}
	result := unknownErr.UnformattedError()
	require.EqualValues(t, result, "")

	unknownErr = &ErrUnknown{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = unknownErr.UnformattedError()
	require.NotEqual(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrUnknown_Annotate(t *testing.T) {
	unknownErr := &ErrUnknown{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                nil, //&sync.RWMutex{},

		},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := unknownErr.Annotate("two", ann)
	require.NotEqual(t, result.Annotations()["two"], ann)

	unknownErr = &ErrUnknown{
		errorCore: &errorCore{
			message:             "math: can't divide by zero",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = unknownErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

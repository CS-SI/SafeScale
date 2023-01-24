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
	"context"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

type BrokenError struct {
	msg      string
	grpcCode uint
}

// data.Annotatable
func (e *BrokenError) Annotate(key string, value data.Annotation) data.Annotatable { return nil }
func (e *BrokenError) Annotations() data.Annotations                               { return nil }
func (e *BrokenError) Annotation(key string) (data.Annotation, bool)               { return nil, false }
func (e *BrokenError) WithContext(ctx context.Context)                             { return }

// causer
func (e *BrokenError) Cause() error     { return nil }
func (e *BrokenError) RootCause() error { return nil }

// consequencer
func (e *BrokenError) Consequences() []error      { return make([]error, 0) }
func (e *BrokenError) AddConsequence(error) Error { return nil }

// error
func (e *BrokenError) Error() string { return e.msg }

// NullValue
func (e *BrokenError) IsNull() bool { return e.msg == "" }

// ToGRPCStatus
func (e *BrokenError) Valid() bool { return e.msg != "" }

// Error
func (e *BrokenError) UnformattedError() string { return e.msg }
func (e *BrokenError) ToGRPCStatus() error      { return nil }

func Test_IgnoreError(t *testing.T) {

	ret := IgnoreError("any", NewError(errors.New("mayday !")))
	require.EqualValues(t, ret, "any")

}

func Test_TakeError(t *testing.T) {

	ret := TakeError("any", NewErrorWithCause(errors.New("any"), "beacauseof"))
	require.Contains(t, ret.Error(), "beacauseof: any")

}

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

	var err *errorCore
	require.EqualValues(t, valid.IsNil(err), true)
	err = &errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}

	require.EqualValues(t, valid.IsNil(err), false)
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
	require.EqualValues(t, valid.IsNil(err), true)
	err = &errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func Test_defaultCauseFormatter(t *testing.T) {

	result := defaultCauseFormatter(nil)
	require.EqualValues(t, result, "")

	berr := &BrokenError{msg: "houston, we have a problem"}
	result = defaultCauseFormatter(berr)

	broken := &ErrUnqualified{
		errorCore: nil,
	}
	result = defaultCauseFormatter(broken)
	require.EqualValues(t, result, "")

	err := &errorCore{
		message:             "houston, we have a problem",
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
		message:             "houston, we have a problem",
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
		message:             "houston, we have a problem",
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
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}

	result = defaultCauseFormatter(err)
	require.EqualValues(t, ": math: can't divide by zero\nwith consequence:\n- can't resolve equation", result)
}

func TestErrorCore_CauseFormatter(t *testing.T) {

	defer func() {
		if r := recover(); r != nil {
			t.Error("Unexpected panic", r)
			t.Fail()
		}
	}()

	var err *errorCore
	_ = err.setCauseFormatter(func(e Error) string {
		return e.Error()
	})

	err = &errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	_ = err.setCauseFormatter(nil)

	err = &errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	_ = err.setCauseFormatter(func(e Error) string {
		return fmt.Sprintf("MyWonderCause: %s", e.Error())
	})
	_ = err.Error()

	err = &errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	_ = err.setCauseFormatter(func(e Error) string {
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
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err := errCore.Unwrap()
	require.EqualValues(t, err.Error(), "math: can't divide by zero")

	errCore = errorCore{
		message:             "houston, we have a problem",
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
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err := errCore.Cause()
	require.EqualValues(t, err.Error(), "math: can't divide by zero")

	errCore = errorCore{
		message:             "houston, we have a problem",
		cause:               nil,
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err = errCore.Cause()
	require.Nil(t, err)

	errCore = errorCore{
		message:             "houston, we have a problem",
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

func TestErrorCore_RootCauseBad(t *testing.T) {
	var panicked error
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer OnPanic(&panicked)
		var err *errorCore
		_ = err.RootCause() // this panics
	}()
	failed := waitTimeout(&wg, 1*time.Second)
	if failed && panicked == nil { // It never ended
		t.FailNow()
	}
}

func TestErrorCore_RootCauseGood(t *testing.T) {
	err := &errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result := err.RootCause()
	require.EqualValues(t, result.Error(), "math: can't divide by zero")

}

func Test_defaultAnnotationFormatter(t *testing.T) {

	var a data.Annotations = nil
	result, _ := defaultAnnotationFormatter(a)
	require.EqualValues(t, result, "")

	a = data.Annotations{
		"test1": 42,
		"test2": "test",
		"test3": 43.92,
		"test4": false,
		"test5": func(a string) string { return a }, // No json.stringify, makes marshall fail
	}
	result, _ = defaultAnnotationFormatter(a)
	require.EqualValues(t, result, "")

	a = data.Annotations{
		"test1": 42,
		"test2": "test",
		"test3": 43.92,
		"test4": false,
	}
	result, _ = defaultAnnotationFormatter(a)
	require.EqualValues(t, result, "{\"test1\":42,\"test2\":\"test\",\"test3\":43.92,\"test4\":false}")

}

func TestErrorCore_Annotations(t *testing.T) {

	errCore := errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	ann := errCore.Annotations()
	require.EqualValues(t, len(ann), 0)

	errCore = errorCore{
		message:             "houston, we have a problem",
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
		message:      "houston, we have a problem",
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
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	_, ok := errCore.Annotation("two")
	require.EqualValues(t, ok, false)

	errCore = errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         nil,
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	_, ok = errCore.Annotation("two")
	require.EqualValues(t, ok, false)

	errCore = errorCore{
		message:      "houston, we have a problem",
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
	ann, ok := errCore.Annotation("two")
	require.EqualValues(t, ok, true)
	require.EqualValues(t, ann, "second")

}

func TestErrorCore_Annotate(t *testing.T) {

	errCore := errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := errCore.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	errCore = errorCore{
		message:             "houston, we have a problem",
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

	var errC *errorCore = nil
	err := errC.setAnnotationFormatter(func(anns data.Annotations) (string, error) {
		return "any", nil
	})
	require.Contains(t, err.Error(), "invalid call: errorCore.setAnnotationFormatter()")
	require.Contains(t, err.Error(), "from null value")

	errCore := errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err = errCore.setAnnotationFormatter(func(anns data.Annotations) (string, error) {
		return "any", nil
	})
	if err != nil {
		t.FailNow()
	}

	errCore = errorCore{
		message:      "houston, we have a problem",
		cause:        errors.New("math: can't divide by zero"),
		consequences: []error{errors.New("can't resolve equation")},
		annotations: data.Annotations{
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
	err = errCore.setAnnotationFormatter(nil)
	if err == nil {
		t.FailNow()
	}
	require.NotEqual(t, strings.Index(errCore.UnformattedError(), "{\"eggs\":{},\"two\":\"second one\"}"), -1)

	err = errCore.setAnnotationFormatter(func(anns data.Annotations) (string, error) {
		if anns == nil {
			return "", nil
		}
		j, err := json.Marshal(anns)
		if err != nil {
			return "", err
		}
		return string(j), nil
	})
	if err != nil {
		t.FailNow()
	}
	require.NotEqual(t, strings.Index(errCore.UnformattedError(), "{\"eggs\":{},\"two\":\"second one\"}"), -1)

}

func TestErrorCore_AddConsequence(t *testing.T) {

	errCore := errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err := errCore.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	errCore = errorCore{
		message:             "houston, we have a problem",
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
		message:             "houston, we have a problem",
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
		message:             "houston, we have a problem",
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

	errCore = errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	perr := &errCore
	err = errCore.AddConsequence(perr)
	require.EqualValues(t, fmt.Sprintf("%p", err), fmt.Sprintf("%p", perr))

}

func TestErrorCore_WithContext(t *testing.T) {

	errCore := errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        nil,
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		errCore.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		errCore.WithContext(context.Background())
	}()
}

func TestErrorCore_Consequences(t *testing.T) {

	errCore := errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	cqs := errCore.Consequences()
	require.EqualValues(t, len(cqs), 1)

	errCore = errorCore{
		message:             "houston, we have a problem",
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
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result := errCore.Error()
	require.EqualValues(t, result, "houston, we have a problem: math: can't divide by zero\nwith consequence:\n- can't resolve equation")

	errCore.lock = &sync.RWMutex{}
	result = errCore.Error()
	require.EqualValues(t, "houston, we have a problem: math: can't divide by zero\nwith consequence:\n- can't resolve equation", result)

	errCore = errorCore{
		message:      "houston, we have a problem",
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
		message:             "houston, we have a problem",
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
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result := errCore.UnformattedError()
	require.EqualValues(t, "houston, we have a problem", result)

	errCore = errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = errCore.UnformattedError()
	require.EqualValues(t, "houston, we have a problem", result)
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrorCore_GRPCCode(t *testing.T) {
	errCore := errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result := errCore.getGRPCCode()
	require.EqualValues(t, result, codes.Unknown)

	errCore = errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.OK,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	result = errCore.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func TestErrorCore_ToGRPCStatus(t *testing.T) {
	errCore := errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.Unknown,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err := errCore.ToGRPCStatus()
	require.EqualValues(t, err.Error(), "rpc error: code = Unknown desc = houston, we have a problem: math: can't divide by zero\nwith consequence:\n- can't resolve equation")

	errCore = errorCore{
		message:             "houston, we have a problem",
		cause:               errors.New("math: can't divide by zero"),
		consequences:        []error{errors.New("can't resolve equation")},
		annotations:         make(data.Annotations),
		grpcCode:            codes.OK,
		causeFormatter:      defaultCauseFormatter,
		annotationFormatter: defaultAnnotationFormatter,
		lock:                &sync.RWMutex{},
	}
	err = errCore.ToGRPCStatus()
	require.Nil(t, err)

	errCore = errorCore{
		message:             "houston, we have a problem",
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

func Test_WarningError(t *testing.T) {
	err := WarningError(errors.New("math: can't divide by zero"), "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrWarning")
}

func Test_WarningErrorWithContext(t *testing.T) {
	err := WarningError(errors.New("math: can't divide by zero"), "Any message")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_WarningErrorWithCauseAndConsequences(t *testing.T) {
	err := WarningErrorWithCauseAndConsequences(errors.New("math: can't divide by zero"), []error{errors.New("it fails")}, "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrWarning")
}

func TestErrWarning_IsNull(t *testing.T) {
	var err *ErrWarning = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrWarning{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrWarning{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrWarning_AddConsequence(t *testing.T) {

	warning := &ErrWarning{
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
	}

	err := warning.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	warning = &ErrWarning{
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
	}
	err = warning.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	warning = &ErrWarning{
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
	}
	_ = warning.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(warning.Consequences()).Error(), "current compute abort"), -1)

	warning = &ErrWarning{
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
	}
	err = warning.AddConsequence(warning)
	require.EqualValues(t, fmt.Sprintf("%p", warning), fmt.Sprintf("%p", err))

}

func TestErrWarning_Annotate(t *testing.T) {

	warning := &ErrWarning{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := warning.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	warning = &ErrWarning{
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
	}
	result = warning.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)
}

func TestErrWarning_UnformattedError(t *testing.T) {

	warning := &ErrWarning{
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
	}
	result := warning.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	warning = &ErrWarning{
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
	}
	result = warning.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrWarning_GRPCCode(t *testing.T) {

	warning := &ErrWarning{
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
	}
	result := warning.getGRPCCode()
	require.EqualValues(t, result, codes.Unknown)

	warning = &ErrWarning{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = warning.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_TimeoutError(t *testing.T) {

	err := TimeoutError(errors.New("math: can't divide by zero"), 30*time.Second, "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrTimeout")
}

func Test_TimeoutErrorWithContext(t *testing.T) {
	err := TimeoutError(errors.New("math: can't divide by zero"), 30*time.Second, "Any message")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func TestErrTimeout_IsNull(t *testing.T) {

	var err *ErrTimeout = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrTimeout{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrTimeout{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrTimeout_AddConsequence(t *testing.T) {

	timeout := &ErrTimeout{
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
	}

	err := timeout.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	timeout = &ErrTimeout{
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
	}
	err = timeout.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	timeout = &ErrTimeout{
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
	}
	_ = timeout.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(timeout.Consequences()).Error(), "current compute abort"), -1)

	timeout = &ErrTimeout{
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
	}
	err = timeout.AddConsequence(timeout)
	require.EqualValues(t, fmt.Sprintf("%p", timeout), fmt.Sprintf("%p", err))

}

func TestErrTimeout_Annotate(t *testing.T) {

	timeout := &ErrTimeout{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := timeout.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	timeout = &ErrTimeout{
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
	}
	result = timeout.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)
}

func TestErrTimeout_UnformattedError(t *testing.T) {

	timeout := &ErrTimeout{
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
	}
	result := timeout.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	timeout = &ErrTimeout{
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
	}
	result = timeout.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrTimeout_GRPCCode(t *testing.T) {

	timeout := &ErrTimeout{
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
	result := timeout.getGRPCCode()
	require.EqualValues(t, result, codes.DeadlineExceeded)

	timeout = &ErrTimeout{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = timeout.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_ErrNotFound(t *testing.T) {
	err := NotFoundError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotFound")
}

func Test_ErrNotFoundWithCtx(t *testing.T) {
	err := NotFoundErrorWithCause(errors.New("math: can't divide by zero"), nil, "Any message")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithCtx(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithCtx(context.Background())
	}()
}

func Test_ErrNotFoundWithContext(t *testing.T) {
	err := NotFoundErrorWithCause(errors.New("math: can't divide by zero"), nil, "Any message")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_NotFoundErrorWithCause(t *testing.T) {
	err := NotFoundErrorWithCause(errors.New("math: can't divide by zero"), nil, "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotFound")
}

func TestErrNotFound_AddConsequence(t *testing.T) {

	notfound := &ErrNotFound{
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
	}

	err := notfound.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	notfound = &ErrNotFound{
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
	}
	err = notfound.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	notfound = &ErrNotFound{
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
	}
	_ = notfound.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(notfound.Consequences()).Error(), "current compute abort"), -1)

	notfound = &ErrNotFound{
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
	}
	err = notfound.AddConsequence(notfound)
	require.EqualValues(t, fmt.Sprintf("%p", notfound), fmt.Sprintf("%p", err))

}

func TestErrNotFound_Annotate(t *testing.T) {
	notfound := &ErrNotFound{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	_ = notfound.Annotate("two", ann)

	notfound = &ErrNotFound{
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
	}
	result := notfound.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrNotFound_UnformattedError(t *testing.T) {

	notfound := &ErrNotFound{
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
	}
	result := notfound.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	notfound = &ErrNotFound{
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
	}
	result = notfound.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrNotFound_GRPCCode(t *testing.T) {

	notfound := &ErrNotFound{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.NotFound,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := notfound.getGRPCCode()
	require.EqualValues(t, result, codes.NotFound)

	notfound = &ErrNotFound{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = notfound.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_ErrNotAvailable(t *testing.T) {
	err := NotAvailableError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotAvailable")
}

func Test_ErrNotAvailableWithContext(t *testing.T) {
	err := NotAvailableError("Any message")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_NotAvailableErrorWithCause(t *testing.T) {
	err := NotAvailableErrorWithCause(errors.New("math: can't divide by zero"), nil, "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotAvailable")
}

func TestErrNotAvailable_IsNull(t *testing.T) {

	var err *ErrNotAvailable = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrNotAvailable{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrNotAvailable{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrNotAvailable_AddConsequence(t *testing.T) {

	notavailable := &ErrNotAvailable{
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
	}

	err := notavailable.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	notavailable = &ErrNotAvailable{
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
	}
	err = notavailable.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	notavailable = &ErrNotAvailable{
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
	}
	_ = notavailable.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(notavailable.Consequences()).Error(), "current compute abort"), -1)

	notavailable = &ErrNotAvailable{
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
	}
	err = notavailable.AddConsequence(notavailable)
	require.EqualValues(t, fmt.Sprintf("%p", notavailable), fmt.Sprintf("%p", err))

}

func TestErrNotAvailable_Annotate(t *testing.T) {
	notavailable := &ErrNotAvailable{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	_ = notavailable.Annotate("two", ann)

	notavailable = &ErrNotAvailable{
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
	}
	result := notavailable.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrNotAvailable_UnformattedError(t *testing.T) {

	notavailable := &ErrNotAvailable{
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
	}
	result := notavailable.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	notavailable = &ErrNotAvailable{
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
	}
	result = notavailable.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrNotAvailable_GRPCCode(t *testing.T) {

	notavailable := &ErrNotAvailable{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unavailable,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := notavailable.getGRPCCode()
	require.EqualValues(t, result, codes.Unavailable)

	notavailable = &ErrNotAvailable{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = notavailable.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_DuplicateError(t *testing.T) {
	err := DuplicateError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrDuplicate")
}

func Test_DuplicateErrorWithContext(t *testing.T) {
	err := DuplicateError(errors.New("math: can't divide by zero"), "Any message")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_DuplicateErrorWithCause(t *testing.T) {
	err := DuplicateErrorWithCause(errors.New("math: can't divide by zero"), nil, "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrDuplicate")
}

func TestDuplicateError_IsNull(t *testing.T) {

	var err *ErrDuplicate = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrDuplicate{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrDuplicate{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrDuplicate_AddConsequence(t *testing.T) {

	duplicateerr := &ErrDuplicate{
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
	}

	err := duplicateerr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	duplicateerr = &ErrDuplicate{
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
	}
	err = duplicateerr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	duplicateerr = &ErrDuplicate{
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
	}
	_ = duplicateerr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(duplicateerr.Consequences()).Error(), "current compute abort"), -1)

	duplicateerr = &ErrDuplicate{
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
	}
	err = duplicateerr.AddConsequence(duplicateerr)
	require.EqualValues(t, fmt.Sprintf("%p", duplicateerr), fmt.Sprintf("%p", err))

}

func TestErrDuplicate_UnformattedError(t *testing.T) {

	duplicateerr := &ErrDuplicate{
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
	}
	result := duplicateerr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	duplicateerr = &ErrDuplicate{
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
	}
	result = duplicateerr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrDuplicate_Annotate(t *testing.T) {
	duplicateerr := &ErrDuplicate{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := duplicateerr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	duplicateerr = &ErrDuplicate{
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
	}
	result = duplicateerr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrDuplicate_GRPCCode(t *testing.T) {

	duplicateerr := &ErrDuplicate{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.AlreadyExists,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := duplicateerr.getGRPCCode()
	require.EqualValues(t, result, codes.AlreadyExists)

	duplicateerr = &ErrDuplicate{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = duplicateerr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_InvalidRequestError(t *testing.T) {
	err := InvalidRequestError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidRequest")
}

func Test_InvalidRequestErrorWithContext(t *testing.T) {
	err := InvalidRequestError("Any message")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_InvalidRequestErrorWithCause(t *testing.T) {
	err := InvalidRequestErrorWithCause(errors.New("houston, we have a problem"), []error{}, "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidRequest")
}

func TestErrInvalidRequest_IsNull(t *testing.T) {

	var err *ErrInvalidRequest = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrInvalidRequest{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrInvalidRequest{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrInvalidRequest_AddConsequence(t *testing.T) {

	invalidreqerr := &ErrInvalidRequest{
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
	}

	err := invalidreqerr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	invalidreqerr = &ErrInvalidRequest{
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
	}
	err = invalidreqerr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	invalidreqerr = &ErrInvalidRequest{
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
	}
	_ = invalidreqerr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(invalidreqerr.Consequences()).Error(), "current compute abort"), -1)

	invalidreqerr = &ErrInvalidRequest{
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
	}
	err = invalidreqerr.AddConsequence(invalidreqerr)
	require.EqualValues(t, fmt.Sprintf("%p", invalidreqerr), fmt.Sprintf("%p", err))

}

func TestErrInvalidRequest_UnformattedError(t *testing.T) {

	invalidreqerr := &ErrInvalidRequest{
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
	}
	result := invalidreqerr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	invalidreqerr = &ErrInvalidRequest{
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
	}
	result = invalidreqerr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrInvalidRequest_Annotate(t *testing.T) {
	invalidreqerr := &ErrInvalidRequest{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := invalidreqerr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	invalidreqerr = &ErrInvalidRequest{
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
	}
	result = invalidreqerr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrInvalidRequest__GRPCCode(t *testing.T) {

	invalidreqerr := &ErrInvalidRequest{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.InvalidArgument,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := invalidreqerr.getGRPCCode()
	require.EqualValues(t, result, codes.InvalidArgument)

	invalidreqerr = &ErrInvalidRequest{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = invalidreqerr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_SyntaxError(t *testing.T) {
	err := SyntaxError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrSyntax")
}

func Test_SyntaxErrorWithContext(t *testing.T) {
	err := SyntaxError("Any message")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_SyntaxErrorWithCause(t *testing.T) {

	err := SyntaxErrorWithCause(errors.New("math: can't divide by zero"), nil, "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrSyntax")

}

func TestErrSyntax_IsNull(t *testing.T) {

	var err *ErrSyntax = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrSyntax{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrSyntax{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrSyntax_AddConsequence(t *testing.T) {

	syntaxerr := &ErrSyntax{
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
	}

	err := syntaxerr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	syntaxerr = &ErrSyntax{
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
	}
	err = syntaxerr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	syntaxerr = &ErrSyntax{
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
	}
	_ = syntaxerr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(syntaxerr.Consequences()).Error(), "current compute abort"), -1)

	syntaxerr = &ErrSyntax{
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
	}
	err = syntaxerr.AddConsequence(syntaxerr)
	require.EqualValues(t, fmt.Sprintf("%p", syntaxerr), fmt.Sprintf("%p", err))

}

func TestErrSyntax_UnformattedError(t *testing.T) {

	var nilErr *ErrSyntax = nil
	require.EqualValues(t, nilErr.UnformattedError(), "")

	syntaxerr := &ErrSyntax{
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
	}
	result := syntaxerr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	syntaxerr = &ErrSyntax{
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
	}
	result = syntaxerr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrSyntax_Annotate(t *testing.T) {
	syntaxerr := &ErrSyntax{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := syntaxerr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	syntaxerr = &ErrSyntax{
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
	}
	result = syntaxerr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrSyntax_GRPCCode(t *testing.T) {

	var nilErr *ErrSyntax = nil
	require.EqualValues(t, nilErr.getGRPCCode(), codes.InvalidArgument)

	syntaxerr := &ErrSyntax{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.InvalidArgument,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := syntaxerr.getGRPCCode()
	require.EqualValues(t, result, codes.InvalidArgument)

	syntaxerr = &ErrSyntax{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = syntaxerr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_NotAuthenticatedError(t *testing.T) {
	err := NotAuthenticatedError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotAuthenticated")
}

func Test_NotAuthenticatedErrorWithContext(t *testing.T) {
	err := NotAuthenticatedError("Any message")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_NotAuthenticatedErrorWithCause(t *testing.T) {
	err := NotAuthenticatedErrorWithCause(errors.New("houston, we have a problem"), []error{}, "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotAuthenticated")
}

func TestErrNotAuthenticated_IsNull(t *testing.T) {

	var err *ErrNotAuthenticated = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrNotAuthenticated{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrNotAuthenticated{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrNotAuthenticated_AddConsequence(t *testing.T) {

	autherr := &ErrNotAuthenticated{
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
	}

	err := autherr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	autherr = &ErrNotAuthenticated{
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
	}
	err = autherr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	autherr = &ErrNotAuthenticated{
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
	}
	_ = autherr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(autherr.Consequences()).Error(), "current compute abort"), -1)

	autherr = &ErrNotAuthenticated{
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
	}
	err = autherr.AddConsequence(autherr)
	require.EqualValues(t, fmt.Sprintf("%p", autherr), fmt.Sprintf("%p", err))

}

func TestErrNotAuthenticated_UnformattedError(t *testing.T) {

	var nilErr *ErrNotAuthenticated = nil
	require.EqualValues(t, nilErr.UnformattedError(), "")

	autherr := &ErrNotAuthenticated{
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
	}
	result := autherr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	autherr = &ErrNotAuthenticated{
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
	}
	result = autherr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrNotAuthenticated_Annotate(t *testing.T) {
	autherr := &ErrNotAuthenticated{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := autherr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	autherr = &ErrNotAuthenticated{
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
	}
	result = autherr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrNotAuthenticated_GRPCCode(t *testing.T) {

	autherr := &ErrNotAuthenticated{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unauthenticated,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := autherr.getGRPCCode()
	require.EqualValues(t, result, codes.Unauthenticated)

	autherr = &ErrNotAuthenticated{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = autherr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_ForbiddenError(t *testing.T) {
	err := ForbiddenError("Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrForbidden")
}

func Test_ForbiddenErrorWithContext(t *testing.T) {
	err := ForbiddenError("Any message")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_ForbiddenErrorWithCause(t *testing.T) {
	err := ForbiddenErrorWithCause(errors.New("houston, we have a problem"), []error{}, "Any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrForbidden")
}

func TestErrForbidden_IsNull(t *testing.T) {

	var err *ErrForbidden = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrForbidden{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrForbidden{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrForbidden_AddConsequence(t *testing.T) {

	forbiderr := &ErrForbidden{
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
	}

	err := forbiderr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	forbiderr = &ErrForbidden{
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
	}
	err = forbiderr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	forbiderr = &ErrForbidden{
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
	}
	_ = forbiderr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(forbiderr.Consequences()).Error(), "current compute abort"), -1)

	forbiderr = &ErrForbidden{
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
	}
	err = forbiderr.AddConsequence(forbiderr)
	require.EqualValues(t, fmt.Sprintf("%p", forbiderr), fmt.Sprintf("%p", err))

}

func TestErrForbidden_UnformattedError(t *testing.T) {

	var nilErr *ErrForbidden = nil
	require.EqualValues(t, nilErr.UnformattedError(), "")

	forbiderr := &ErrForbidden{
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
	}
	result := forbiderr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	forbiderr = &ErrForbidden{
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
	}
	result = forbiderr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrForbidden_Annotate(t *testing.T) {
	forbiderr := &ErrForbidden{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := forbiderr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	forbiderr = &ErrForbidden{
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
	}
	result = forbiderr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrForbidden_GRPCCode(t *testing.T) {

	forbiderr := &ErrForbidden{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.PermissionDenied,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := forbiderr.getGRPCCode()
	require.EqualValues(t, result, codes.PermissionDenied)

	forbiderr = &ErrForbidden{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = forbiderr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_AbortedError(t *testing.T) {
	err := AbortedError(errors.New("math: can't divide by zero"), "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrAborted")
	err = AbortedError(errors.New(""))
	require.EqualValues(t, err.Error(), "aborted")
}

func Test_AbortedErrorWithContext(t *testing.T) {
	err := AbortedError(errors.New("math: can't divide by zero"), "any error")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_AbortedErrorWithCauseAndConsequences(t *testing.T) {
	err := AbortedErrorWithCauseAndConsequences(errors.New("math: can't divide by zero"), []error{}, "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrAborted")
	err = AbortedErrorWithCauseAndConsequences(errors.New("math: can't divide by zero"), []error{})
	require.Contains(t, err.Error(), "aborted")
}

func TestErrAborted_IsNull(t *testing.T) {

	var err *ErrAborted = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrAborted{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrAborted{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrAborted_AddConsequence(t *testing.T) {

	aborterr := &ErrAborted{
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
	}

	err := aborterr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	aborterr = &ErrAborted{
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
	}
	err = aborterr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	aborterr = &ErrAborted{
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
	}
	_ = aborterr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(aborterr.Consequences()).Error(), "current compute abort"), -1)

	aborterr = &ErrAborted{
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
	}
	err = aborterr.AddConsequence(aborterr)
	require.EqualValues(t, fmt.Sprintf("%p", aborterr), fmt.Sprintf("%p", err))

}

func TestErrAborted_UnformattedError(t *testing.T) {

	var nilErr *ErrAborted = nil
	require.EqualValues(t, nilErr.UnformattedError(), "")

	aborterr := &ErrAborted{
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
	}
	result := aborterr.UnformattedError()
	require.EqualValues(t, "houston, we have a problem", result)

	aborterr = &ErrAborted{
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
	}
	result = aborterr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)
}

func TestErrAborted_Annotate(t *testing.T) {
	aborterr := &ErrAborted{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := aborterr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	aborterr = &ErrAborted{
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
	}
	result = aborterr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrAborted_GRPCCode(t *testing.T) {

	aborterr := &ErrAborted{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Aborted,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := aborterr.getGRPCCode()
	require.EqualValues(t, result, codes.Aborted)

	aborterr = &ErrAborted{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = aborterr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_OverflowError(t *testing.T) {
	err := OverflowError(errors.New("math: can't divide by zero"), 30, "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrOverflow")
}

func Test_OverflowErrorWithContext(t *testing.T) {
	err := OverflowError(errors.New("math: can't divide by zero"), 30, "any error")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_OverflowErrorWithCause(t *testing.T) {
	err := OverflowErrorWithCause(errors.New("math: can't divide by zero"), 30, []error{}, "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrOverflow")
}

func TestErrOverflow_IsNull(t *testing.T) {

	var err *ErrOverflow = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrOverflow{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrOverflow{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrOverflow_AddConsequence(t *testing.T) {

	ovflowterr := &ErrOverflow{
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
	}

	err := ovflowterr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	ovflowterr = &ErrOverflow{
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
	}
	err = ovflowterr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	ovflowterr = &ErrOverflow{
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
	}
	_ = ovflowterr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(ovflowterr.Consequences()).Error(), "current compute abort"), -1)

	ovflowterr = &ErrOverflow{
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
	}
	err = ovflowterr.AddConsequence(ovflowterr)
	require.EqualValues(t, fmt.Sprintf("%p", ovflowterr), fmt.Sprintf("%p", err))

}

func TestErrOverflow_UnformattedError(t *testing.T) {

	var nilErr *ErrOverflow = nil
	require.EqualValues(t, nilErr.UnformattedError(), "")

	ovflowterr := &ErrOverflow{
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
	}
	result := ovflowterr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	ovflowterr = &ErrOverflow{
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
	}
	result = ovflowterr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrOverflow_Annotate(t *testing.T) {
	ovflowterr := &ErrOverflow{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := ovflowterr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	ovflowterr = &ErrOverflow{
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
	}
	result = ovflowterr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrOverflow_GRPCCode(t *testing.T) {

	ovflowterr := &ErrOverflow{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OutOfRange,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := ovflowterr.getGRPCCode()
	require.EqualValues(t, result, codes.OutOfRange)

	ovflowterr = &ErrOverflow{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = ovflowterr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_OverloadError(t *testing.T) {
	err := OverloadError("any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrOverload")
}

func Test_OverloadErrorWithContext(t *testing.T) {
	err := OverloadError("any error")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_OverloadErrorWithCause(t *testing.T) {
	err := OverloadErrorWithCause(errors.New("houston, we have a problem"), []error{}, "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrOverload")
}

func TestErrOverload_IsNull(t *testing.T) {

	var err *ErrOverload = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrOverload{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrOverload{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrOverload_AddConsequence(t *testing.T) {

	overloadErr := &ErrOverload{
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
	}

	err := overloadErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	overloadErr = &ErrOverload{
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
	}
	err = overloadErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	overloadErr = &ErrOverload{
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
	}
	_ = overloadErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(overloadErr.Consequences()).Error(), "current compute abort"), -1)

	overloadErr = &ErrOverload{
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
	}
	err = overloadErr.AddConsequence(overloadErr)
	require.EqualValues(t, fmt.Sprintf("%p", overloadErr), fmt.Sprintf("%p", err))

}

func TestErrOverload_UnformattedError(t *testing.T) {

	overloadErr := &ErrOverload{
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
	}
	result := overloadErr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	overloadErr = &ErrOverload{
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
	}
	result = overloadErr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrOverload_Annotate(t *testing.T) {
	overloadErr := &ErrOverload{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := overloadErr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	overloadErr = &ErrOverload{
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
	}
	result = overloadErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrOverload_GRPCCode(t *testing.T) {

	overloadErr := &ErrOverload{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.ResourceExhausted,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := overloadErr.getGRPCCode()
	require.EqualValues(t, result, codes.ResourceExhausted)

	overloadErr = &ErrOverload{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = overloadErr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_NotImplementedError(t *testing.T) {
	err := NotImplementedError("any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotImplemented")
}

func Test_NotImplementedErrorWithContext(t *testing.T) {
	err := NotImplementedError("any error")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_NotImplementedErrorWithReason(t *testing.T) {
	err := NotImplementedErrorWithCauseAndConsequences(nil, nil, "any error", "cause")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotImplemented")
}

func TestErrNotImplemented_IsNull(t *testing.T) {
	var err *ErrNotImplemented = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrNotImplemented{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrNotImplemented{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrNotImplemented_AddConsequence(t *testing.T) {

	notImplementedErr := &ErrNotImplemented{
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
	}

	err := notImplementedErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	notImplementedErr = &ErrNotImplemented{
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
	}
	err = notImplementedErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	notImplementedErr = &ErrNotImplemented{
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
	}
	_ = notImplementedErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(notImplementedErr.Consequences()).Error(), "current compute abort"), -1)

	notImplementedErr = &ErrNotImplemented{
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
	}
	err = notImplementedErr.AddConsequence(notImplementedErr)
	require.EqualValues(t, fmt.Sprintf("%p", notImplementedErr), fmt.Sprintf("%p", err))

}

func TestErrNotImplemented_UnformattedError(t *testing.T) {

	var errNil *ErrNotImplemented = nil
	require.EqualValues(t, errNil.UnformattedError(), "")

	notImplementedErr := &ErrNotImplemented{
		errorCore: &errorCore{
			message:             "Houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := notImplementedErr.UnformattedError()
	require.EqualValues(t, "Houston, we have a problem", result)

	notImplementedErr = &ErrNotImplemented{
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
	}
	result = notImplementedErr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrNotImplemented_Annotate(t *testing.T) {
	notImplementedErr := &ErrNotImplemented{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := notImplementedErr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	notImplementedErr = &ErrNotImplemented{
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
	}
	result = notImplementedErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrNotImplemented_GRPCCode(t *testing.T) {

	notImplementedErr := &ErrNotImplemented{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Unimplemented,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := notImplementedErr.getGRPCCode()
	require.EqualValues(t, result, codes.Unimplemented)

	notImplementedErr = &ErrNotImplemented{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = notImplementedErr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_RuntimePanicError(t *testing.T) {
	err := RuntimePanicError("pattern %s", "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrRuntimePanic")
}

func Test_RuntimePanicErrorWithCauseAndConsequences(t *testing.T) {
	err := RuntimePanicErrorWithCauseAndConsequences(errors.New("houston, we have a problem"), []error{}, false, "pattern %s", "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrRuntimePanic")
}

func TestErrRuntimePanic_IsNull(t *testing.T) {

	var err *ErrRuntimePanic = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrRuntimePanic{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrRuntimePanic{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrRuntimePanic_AddConsequence(t *testing.T) {

	runtimePanicErr := &ErrRuntimePanic{
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
	}

	err := runtimePanicErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	runtimePanicErr = &ErrRuntimePanic{
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
	}
	err = runtimePanicErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	runtimePanicErr = &ErrRuntimePanic{
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
	}
	_ = runtimePanicErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(runtimePanicErr.Consequences()).Error(), "current compute abort"), -1)

	runtimePanicErr = &ErrRuntimePanic{
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
	}
	err = runtimePanicErr.AddConsequence(runtimePanicErr)
	require.EqualValues(t, fmt.Sprintf("%p", runtimePanicErr), fmt.Sprintf("%p", err))

}

func TestErrRuntimePanic_UnformattedError(t *testing.T) {

	runtimePanicErr := &ErrRuntimePanic{
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
	}
	result := runtimePanicErr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	runtimePanicErr = &ErrRuntimePanic{
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
	}
	result = runtimePanicErr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrRuntimePanic_Annotate(t *testing.T) {
	runtimePanicErr := &ErrRuntimePanic{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := runtimePanicErr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	runtimePanicErr = &ErrRuntimePanic{
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
	}
	result = runtimePanicErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrRuntimePanic_GRPCCode(t *testing.T) {

	runtimePanicErr := &ErrRuntimePanic{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Internal,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := runtimePanicErr.getGRPCCode()
	require.EqualValues(t, result, codes.Internal)

	runtimePanicErr = &ErrRuntimePanic{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = runtimePanicErr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_InvalidInstanceError(t *testing.T) {
	err := InvalidInstanceError()
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstance")
}

func Test_InvalidInstanceErrorWithContext(t *testing.T) {
	err := InvalidInstanceError()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_InvalidInstanceErrorWithCause(t *testing.T) {
	err := InvalidInstanceErrorWithCause(errors.New("houston, we have a problem"), []error{}, "any message")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstance")
}

func TestErrInvalidInstance_IsNull(t *testing.T) {

	var err *ErrInvalidInstance = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrInvalidInstance{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrInvalidInstance{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrInvalidInstance_AddConsequence(t *testing.T) {

	invalidInstanceErr := &ErrInvalidInstance{
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
	}

	err := invalidInstanceErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	invalidInstanceErr = &ErrInvalidInstance{
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
	}
	err = invalidInstanceErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	invalidInstanceErr = &ErrInvalidInstance{
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
	}
	_ = invalidInstanceErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(invalidInstanceErr.Consequences()).Error(), "current compute abort"), -1)

	invalidInstanceErr = &ErrInvalidInstance{
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
	}
	err = invalidInstanceErr.AddConsequence(invalidInstanceErr)
	require.EqualValues(t, fmt.Sprintf("%p", invalidInstanceErr), fmt.Sprintf("%p", err))

}

func TestErrInvalidInstance_UnformattedError(t *testing.T) {

	invalidInstanceErr := &ErrInvalidInstance{
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
	}
	result := invalidInstanceErr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	invalidInstanceErr = &ErrInvalidInstance{
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
	}
	result = invalidInstanceErr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrInvalidInstance_Annotate(t *testing.T) {
	invalidInstanceErr := &ErrInvalidInstance{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := invalidInstanceErr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	invalidInstanceErr = &ErrInvalidInstance{
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
	}
	result = invalidInstanceErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrInvalidInstance_GRPCCode(t *testing.T) {

	invalidInstanceErr := &ErrInvalidInstance{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.FailedPrecondition,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := invalidInstanceErr.getGRPCCode()
	require.EqualValues(t, result, codes.FailedPrecondition)

	invalidInstanceErr = &ErrInvalidInstance{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = invalidInstanceErr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_InvalidParameterError(t *testing.T) {
	err := InvalidParameterError("what is it", "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
}

func Test_InvalidParameterErrorWithContext(t *testing.T) {
	err := InvalidParameterError("what is it", "any error")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_InvalidParameterErrorWithCauseAndConsequences(t *testing.T) {
	err := InvalidParameterErrorWithCauseAndConsequences(errors.New("houston, we have a problem"), []error{}, "what is it", 1, "any error")
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
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrInvalidParameter{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrInvalidParameter{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrInvalidParameter_AddConsequence(t *testing.T) {

	invalidParameterErr := &ErrInvalidParameter{
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
	}

	err := invalidParameterErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	invalidParameterErr = &ErrInvalidParameter{
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
	}
	err = invalidParameterErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	invalidParameterErr = &ErrInvalidParameter{
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
	}
	_ = invalidParameterErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(invalidParameterErr.Consequences()).Error(), "current compute abort"), -1)

	invalidParameterErr = &ErrInvalidParameter{
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
	}
	err = invalidParameterErr.AddConsequence(invalidParameterErr)
	require.EqualValues(t, fmt.Sprintf("%p", invalidParameterErr), fmt.Sprintf("%p", err))

}

func TestErrInvalidParameter_UnformattedError(t *testing.T) {

	invalidParameterErr := &ErrInvalidParameter{
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
	}
	result := invalidParameterErr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	invalidParameterErr = &ErrInvalidParameter{
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
	}
	result = invalidParameterErr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrInvalidParameter_Annotate(t *testing.T) {
	invalidParameterErr := &ErrInvalidParameter{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := invalidParameterErr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	invalidParameterErr = &ErrInvalidParameter{
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
	}
	result = invalidParameterErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrInvalidParameter_GRPCCode(t *testing.T) {

	invalidParameterErr := &ErrInvalidParameter{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.InvalidArgument,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := invalidParameterErr.getGRPCCode()
	require.EqualValues(t, result, codes.InvalidArgument)

	invalidParameterErr = &ErrInvalidParameter{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = invalidParameterErr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_InvalidInstanceContentError(t *testing.T) {
	err := InvalidInstanceContentError("what is it", "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstanceContent")
}

func Test_InvalidInstanceContentErrorWithContext(t *testing.T) {
	err := InvalidInstanceContentError("what is it", "any error")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_InvalidInstanceContentErrorWithCause(t *testing.T) {
	err := InvalidInstanceContentErrorWithCause(errors.New("houston, we have a problem"), []error{}, "what is it", "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidInstanceContent")
}

func TestErrInvalidInstanceContent_IsNull(t *testing.T) {

	var err *ErrInvalidInstanceContent = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrInvalidInstanceContent{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrInvalidInstanceContent{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrInvalidInstanceContent_AddConsequence(t *testing.T) {

	invalidInstanceContentErr := &ErrInvalidInstanceContent{
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
	}

	err := invalidInstanceContentErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	invalidInstanceContentErr = &ErrInvalidInstanceContent{
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
	}
	err = invalidInstanceContentErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	invalidInstanceContentErr = &ErrInvalidInstanceContent{
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
	}
	_ = invalidInstanceContentErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(invalidInstanceContentErr.Consequences()).Error(), "current compute abort"), -1)

	invalidInstanceContentErr = &ErrInvalidInstanceContent{
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
	}
	err = invalidInstanceContentErr.AddConsequence(invalidInstanceContentErr)
	require.EqualValues(t, fmt.Sprintf("%p", invalidInstanceContentErr), fmt.Sprintf("%p", err))

}

func TestErrInvalidInstanceContent_UnformattedError(t *testing.T) {

	invalidInstanceContentErr := &ErrInvalidInstanceContent{
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
	}
	result := invalidInstanceContentErr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	invalidInstanceContentErr = &ErrInvalidInstanceContent{
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
	}
	result = invalidInstanceContentErr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrInvalidInstanceContent_Annotate(t *testing.T) {
	invalidInstanceContentErr := &ErrInvalidInstanceContent{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := invalidInstanceContentErr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	invalidInstanceContentErr = &ErrInvalidInstanceContent{
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
	}
	result = invalidInstanceContentErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrInvalidInstanceContent_GRPCCode(t *testing.T) {

	invalidInstanceContentErr := &ErrInvalidInstanceContent{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.FailedPrecondition,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := invalidInstanceContentErr.getGRPCCode()
	require.EqualValues(t, result, codes.FailedPrecondition)

	invalidInstanceContentErr = &ErrInvalidInstanceContent{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = invalidInstanceContentErr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_InconsistentError(t *testing.T) {
	err := InconsistentError("any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInconsistent")
}

func Test_InconsistentErrorWithContext(t *testing.T) {
	err := InconsistentError("any error")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_InconsistentErrorWithCause(t *testing.T) {
	err := InconsistentErrorWithCause(errors.New("houston, we have a problem"), []error{}, "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInconsistent")
}

func TestErrInconsistent_IsNull(t *testing.T) {

	var err *ErrInconsistent = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrInconsistent{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrInconsistent{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrInconsistent_AddConsequence(t *testing.T) {

	inconsistentErr := &ErrInconsistent{
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
	}

	err := inconsistentErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	inconsistentErr = &ErrInconsistent{
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
	}
	err = inconsistentErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	inconsistentErr = &ErrInconsistent{
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
	}
	_ = inconsistentErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(inconsistentErr.Consequences()).Error(), "current compute abort"), -1)

	inconsistentErr = &ErrInconsistent{
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
	}
	err = inconsistentErr.AddConsequence(inconsistentErr)
	require.EqualValues(t, fmt.Sprintf("%p", inconsistentErr), fmt.Sprintf("%p", err))

}

func TestErrInconsistent_UnformattedError(t *testing.T) {

	inconsistentErr := &ErrInconsistent{
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
	}
	result := inconsistentErr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	inconsistentErr = &ErrInconsistent{
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
	}
	result = inconsistentErr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrInconsistent_Annotate(t *testing.T) {
	inconsistentErr := &ErrInconsistent{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := inconsistentErr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	inconsistentErr = &ErrInconsistent{
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
	}
	result = inconsistentErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrInconsistent_GRPCCode(t *testing.T) {

	inconsistentErr := &ErrInconsistent{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.DataLoss,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := inconsistentErr.getGRPCCode()
	require.EqualValues(t, result, codes.DataLoss) // FIXME: DataLoss ??

	inconsistentErr = &ErrInconsistent{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = inconsistentErr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_ExecutionError(t *testing.T) {
	xerr := ExecutionError(errors.New("exit error"), "any error")
	require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrExecution")
	require.Contains(t, xerr.Error(), "any error")

	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("timeout", "10")
	} else {
		cmd = exec.Command("bash", "-c", "sleep 10")
	}

	if err := cmd.Start(); err != nil {
		t.Error(err)
		t.Fail()
	} else {
		err := cmd.Process.Kill()
		if err != nil {
			t.FailNow()
		}

		err = cmd.Wait()
		if reflect.TypeOf(err).String() == "*exec.ExitError" {
			xerr = ExecutionError(err, "any error")
			require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrExecution")
			require.Contains(t, xerr.Error(), "any error")
			if runtime.GOOS != "windows" {
				require.Contains(t, xerr.Error(), "signal: killed")
			}
		}
	}
}

func Test_ExecutionErrorWithContext(t *testing.T) {
	xerr := ExecutionError(errors.New("exit error"), "any error")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		xerr.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		xerr.WithContext(context.Background())
	}()
}

func Test_ExecutionErrorWithCause(t *testing.T) {
	xerr := ExecutionErrorWithCause(errors.New("exit error"), []error{}, "any error")
	require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrExecution")
	require.Contains(t, xerr.Error(), "any error")
}

func TestErrExecution_IsNull(t *testing.T) {

	var err *ErrExecution = nil
	require.EqualValues(t, valid.IsNil(err), true)
	require.EqualValues(t, valid.IsNull(err), true)

	err = &ErrExecution{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)
	require.EqualValues(t, valid.IsNull(err), false)

	err = &ErrExecution{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         data.Annotations{"retcode": errors.New("-1")},
			grpcCode:            codes.Unknown,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}

	require.EqualValues(t, valid.IsNil(err), false)
	require.EqualValues(t, valid.IsNull(err), false)

}

func TestErrExecution_AddConsequence(t *testing.T) {

	executionErr := &ErrExecution{
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
	}

	err := executionErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	executionErr = &ErrExecution{
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
	}
	err = executionErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	executionErr = &ErrExecution{
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
	}
	_ = executionErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(executionErr.Consequences()).Error(), "current compute abort"), -1)

	executionErr = &ErrExecution{
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
	}
	err = executionErr.AddConsequence(executionErr)
	require.EqualValues(t, fmt.Sprintf("%p", executionErr), fmt.Sprintf("%p", err))

}

func TestErrExecution_UnformattedError(t *testing.T) {

	executionErr := &ErrExecution{
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
	}
	result := executionErr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	executionErr = &ErrExecution{
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
	}
	result = executionErr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrExecution_Annotate(t *testing.T) {
	executionErr := &ErrExecution{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := executionErr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	executionErr = &ErrExecution{
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
	}
	result = executionErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrExecution_GRPCCode(t *testing.T) {

	executionErr := &ErrExecution{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.Internal,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := executionErr.getGRPCCode()
	require.EqualValues(t, result, codes.Internal)

	executionErr = &ErrExecution{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = executionErr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_AlteredNothingError(t *testing.T) {
	err := AlteredNothingError("any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrAlteredNothing")
}

func Test_AlteredNothingErrorWithContext(t *testing.T) {
	err := AlteredNothingError("any error")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_AlteredNothingErrorWithCause(t *testing.T) {
	err := AlteredNothingErrorWithCause(errors.New("houston, we have a problem"), []error{}, "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrAlteredNothing")
}

func TestErrAlteredNothing_IsNull(t *testing.T) {

	var err *ErrAlteredNothing = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrAlteredNothing{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrAlteredNothing{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrAlteredNothing_AddConsequence(t *testing.T) {

	alteredNilErr := &ErrAlteredNothing{
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
	}

	err := alteredNilErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	alteredNilErr = &ErrAlteredNothing{
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
	}
	err = alteredNilErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	alteredNilErr = &ErrAlteredNothing{
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
	}
	_ = alteredNilErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(alteredNilErr.Consequences()).Error(), "current compute abort"), -1)

	alteredNilErr = &ErrAlteredNothing{
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
	}
	err = alteredNilErr.AddConsequence(alteredNilErr)
	require.EqualValues(t, fmt.Sprintf("%p", alteredNilErr), fmt.Sprintf("%p", err))

}

func TestErrAlteredNothing_UnformattedError(t *testing.T) {

	alteredNilErr := &ErrAlteredNothing{
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
	}
	result := alteredNilErr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	alteredNilErr = &ErrAlteredNothing{
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
	}
	result = alteredNilErr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrAlteredNothing_Annotate(t *testing.T) {
	alteredNilErr := &ErrAlteredNothing{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := alteredNilErr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	alteredNilErr = &ErrAlteredNothing{
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
	}
	result = alteredNilErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrAlteredNothing_GRPCCode(t *testing.T) {

	alteredNilErr := &ErrAlteredNothing{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.PermissionDenied,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result := alteredNilErr.getGRPCCode()
	require.EqualValues(t, result, codes.PermissionDenied)

	alteredNilErr = &ErrAlteredNothing{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = alteredNilErr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

func Test_UnknownError(t *testing.T) {
	err := UnknownError("any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrUnknown")
}

func Test_UnknownErrorWithContext(t *testing.T) {
	err := UnknownError("any error")
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(nil)
	}()
	func() {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		err.WithContext(context.Background())
	}()
}

func Test_UnknownErrorWithCause(t *testing.T) {
	err := UnknownErrorWithCause(errors.New("houston, we have a problem"), []error{}, "any error")
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrUnknown")
}

func TestErrUnknown_IsNull(t *testing.T) {

	var err *ErrUnknown = nil
	require.EqualValues(t, valid.IsNil(err), true)

	err = &ErrUnknown{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

	err = &ErrUnknown{
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
	}
	require.EqualValues(t, valid.IsNil(err), false)

}

func TestErrUnknown_AddConsequence(t *testing.T) {

	unknownErr := &ErrUnknown{
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
	}

	err := unknownErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, err, nil)

	unknownErr = &ErrUnknown{
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
	}
	err = unknownErr.AddConsequence(nil)
	require.NotEqual(t, err, nil)

	unknownErr = &ErrUnknown{
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
	}
	_ = unknownErr.AddConsequence(errors.New("current compute abort"))
	require.NotEqual(t, strings.Index(NewErrorList(unknownErr.Consequences()).Error(), "current compute abort"), -1)

	unknownErr = &ErrUnknown{
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
	}
	err = unknownErr.AddConsequence(unknownErr)
	require.EqualValues(t, fmt.Sprintf("%p", unknownErr), fmt.Sprintf("%p", err))

}

func TestErrUnknown_UnformattedError(t *testing.T) {

	unknownErr := &ErrUnknown{
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
	}
	result := unknownErr.UnformattedError()
	require.EqualValues(t, result, "houston, we have a problem")

	unknownErr = &ErrUnknown{
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
	}
	result = unknownErr.UnformattedError()
	require.Equal(t, strings.Index(result, "math: can't divide by zero"), -1)

}

func TestErrUnknown_Annotate(t *testing.T) {
	unknownErr := &ErrUnknown{
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
	}
	ann := map[string]interface{}{
		"two": "second one",
		"eggs": struct {
			source string
			price  float64
		}{"chicken", 1.75},
	}
	result := unknownErr.Annotate("two", ann)
	require.Equal(t, result.Annotations()["two"], ann)

	unknownErr = &ErrUnknown{
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
	}
	result = unknownErr.Annotate("two", ann)
	require.EqualValues(t, result.Annotations()["two"], ann)

}

func TestErrUnknown_GRPCCode(t *testing.T) {

	unknownErr := &ErrUnknown{
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
	}
	result := unknownErr.getGRPCCode()
	require.EqualValues(t, result, codes.Unknown)

	unknownErr = &ErrUnknown{
		errorCore: &errorCore{
			message:             "houston, we have a problem",
			cause:               errors.New("math: can't divide by zero"),
			consequences:        []error{errors.New("can't resolve equation")},
			annotations:         make(data.Annotations),
			grpcCode:            codes.OK,
			causeFormatter:      defaultCauseFormatter,
			annotationFormatter: defaultAnnotationFormatter,
			lock:                &sync.RWMutex{},
		},
	}
	result = unknownErr.getGRPCCode()
	require.EqualValues(t, result, codes.OK)

}

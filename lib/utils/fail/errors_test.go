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
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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

// ---------------------------------------------------------------------------------------------------------------

func generateErrTimeout() *ErrTimeout {
	return TimeoutError(nil, 2*time.Minute, "ouch")
}

func generateErrNilTimeout() *ErrTimeout {
	return nil
}

func generateNilNewError() *errorCore {
	return nil
}

func noProblems() Error {
	return nil
}

func TestAFailErrorisAnError(t *testing.T) {
	var what error
	tfe := NewError("ouch")
	what = tfe
	if what == nil {
		t.Errorf("Cannot be")
	}
}

func TestNormalUsage(t *testing.T) {
	av := TimeoutError(nil, 2*time.Minute, "ouch")
	if av != nil {
		av.CauseFormatter(
			func(e Error) string {
				return "toto"
			})
	}
}

func TestAWellBuiltErrorIsNotNil(t *testing.T) {
	ha := newError(nil, nil, nil)
	if ha.IsNull() {
		t.Fail()
	}
}

func TestAManuallyCreatedInternalErrorMightBeNil(t *testing.T) {
	ha := errorCore{
		message:             "",
		cause:               nil,
		causeFormatter:      nil,
		annotations:         nil,
		annotationFormatter: nil,
		consequences:        nil,
		grpcCode:            33,
	}

	if !ha.IsNull() {
		t.Fail()
	}
}

func TestCanonical(t *testing.T) {
	e := TimeoutError(fmt.Errorf("ouch"), 1)
	e.CauseFormatter(
		func(e Error) string {
			return "toto"
		})
}

func TestNilNormalUsage(t *testing.T) {
	av := generateErrNilTimeout()
	if av != nil {
		av.CauseFormatter(
			func(e Error) string {
				return "toto"
			})
	}
}

// this test breaks no matter what, the first line of CauseFormatter being 'if e.isNull()' of 'if e == nil' makes no difference
func TestNilNormalUsageSkippingNilCheck(t *testing.T) {
	defer func() {
		if x := recover(); x == nil {
			t.Fail()
		}
	}()

	av := generateErrNilTimeout()
	av.CauseFormatter(
		func(e Error) string {
			return "toto"
		})
}

// this test breaks no matter what, the first line of CauseFormatter being 'if e.isNull()' of 'if e == nil' makes no difference
func TestNilInternalUsageSkippingNilCheck(t *testing.T) {
	defer func() {
		if x := recover(); x != nil {
			t.Fail()
		}
	}()

	av := generateNilNewError()
	av.CauseFormatter(
		func(e Error) string {
			return "toto"
		})
}

func TestFromPointerUsage(t *testing.T) {
	av := generateErrTimeout()
	if av != nil {
		av.CauseFormatter(
			func(e Error) string {
				return "toto"
			})
	}
}

func TestInterfaceMatching(t *testing.T) {
	var ok bool

	{
		val := AbortedError(nil)
		_, ok = interface{}(val).(Error)
		assert.True(t, ok)
		_, ok = interface{}(val).(error)
		assert.True(t, ok)
	}

	{
		val := DuplicateError()
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrDuplicate doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrDuplicate doesn't satisfy interface error")
		}
	}

	{
		val := NewErrorList(nil)
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*errorList doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*errorList doesn't satisfy interface error")
		}
	}

	{
		val := ForbiddenError()
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrForbidden doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrForbidden doesn't satisfy interface error")
		}
	}

	{
		val := InconsistentError()
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrInconsistent doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrInconsistent doesn't satisfy interface error")
		}
	}

	{
		val := InvalidInstanceError()
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*errInvalidInstance doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*errInvalidInstance doesn't satisfy interface error")
		}
	}

	{
		val := InvalidInstanceContentError("", "")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrInvalidInstanceContent doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrInvalidInstanceContent doesn't satisfy interface error")
		}
	}

	{
		val := InvalidParameterError("", "")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrInvalidParameter doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrInvalidParameter doesn't satisfy interface error")
		}
	}

	{
		val := InvalidRequestError()
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrInvalidRequest doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrInvalidRequest doesn't satisfy interface error")
		}
	}

	{
		val := NotAuthenticatedError()
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrNotAuthenticated doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrNotAuthenticated doesn't satisfy interface error")
		}
	}

	{
		val := NotAvailableError()
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrNotAvailable doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrNotAvailable doesn't satisfy interface error")
		}
	}

	{
		val := NotFoundError("")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrNotFound doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrNotFound doesn't satisfy interface error")
		}
	}

	{
		val := NotImplementedError("")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrNotImplemented doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrNotImplemented doesn't satisfy interface error")
		}
	}

	{
		val := OverflowError(nil, 1)
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrOverflow doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrOverflow doesn't satisfy interface error")
		}
	}

	{
		val := OverloadError("")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrOverload doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrOverload doesn't satisfy interface error")
		}
	}

	{
		val := RuntimePanicError("")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrRuntimePanic doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrRuntimePanic doesn't satisfy interface error")
		}
	}

	{
		val := SyntaxError("")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ErrSyntax doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ErrSyntax doesn't satisfy interface error")
		}
	}

	{
		val := TimeoutError(nil, 1)
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplTimeout doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplTimeout doesn't satisfy interface error")
		}
	}
}

func lazyDevs() error {
	return NotImplementedError("no time for this")
}

func TestNotImplementedReport(t *testing.T) {
	what := lazyDevs()
	if what == nil {
		t.Fatalf("unexpected nil error")
	}
	whatContent := what.Error()
	if !strings.Contains(whatContent, "fail.lazyDevs") {
		t.Errorf("Expected 'utils.lazyDevs' in error content but found: %s", whatContent)
	}
}

func TestEnrichedReport(t *testing.T) {
	x := moreLazyErrors()
	x = Annotate(x, "region", "europe1")
	x = AddConsequence(x, fmt.Errorf("connection lost"))
	assert.NotNil(t, x)

	errct := x.Error()
	assert.NotNil(t, errct)
	if !strings.Contains(errct, "europe1") {
		t.Errorf("Information loss: %s", errct)
	}
	if !strings.Contains(errct, "connection") {
		t.Errorf("Information loss : %s", errct)
	}
}

func TestWithAnnotations(t *testing.T) {
	x := lazyDevsWithCaveat()
	assert.NotNil(t, x)

	errct := x.Error()
	if !strings.Contains(errct, "Lazy") {
		t.Errorf("We lost the what ! : %s", errct)
	}
	if !strings.Contains(errct, "API not ready") {
		t.Errorf("We lost the why ! : %s", errct)
	}

	x = lazyDevsPlainAndSimple()
	assert.NotNil(t, x)

	errct = x.Error()
	if !strings.Contains(errct, "lazyDevsPlainAndSimple") {
		t.Errorf("We lost the function name ! : %s", errct)
	}
}

func TestWithAnnotationsAgain(t *testing.T) {
	x := moreLazyErrors()
	assert.NotNil(t, x)

	errct := x.Error()
	if !strings.Contains(errct, "host-x") {
		t.Errorf("We lost a key ! : %s", errct)
	}
	if !strings.Contains(errct, "OWH") {
		t.Errorf("We lost a value ! : %s", errct)
	}
}

func TestIsError(t *testing.T) {
	x := moreLazyErrors()
	assert.NotNil(t, x)

	iserr := IsError(x)
	if !iserr {
		t.Errorf("This should be an error! : %s", x)
	}
}

func getNotFoundError() error {
	return NotFoundError("not there !!!")
}

func lazyDevsWithCaveat() error {
	r := NotImplementedErrorWithReason("LazyDevsWithCaveat()", "API not ready")
	r.Annotate("provider", "Juawei")
	return r
}

func lazyDevsPlainAndSimple() error {
	r := NotImplementedError("")
	r.Annotate("provider", "Juawei")
	return r
}

func moreLazyErrors() error {
	r := NotFoundError("We lost something !!")
	r.Annotate("node", "host-x").Annotate("provider", "OWH")
	return r
}

func getNotFoundErrorWithAnnotations() error {
	r := NotFoundError("We lost something !!")
	r.Annotate("node", "host-x").Annotate("provider", "OWH")
	return r
}

func getNotFoundErrorWithAnnotationsAndConsequences() error {
	nfe := NotFoundError("We lost something !!")
	nfe.Annotate("node", "host-x").Annotate("provider", "OWH")
	return AddConsequence(nfe, fmt.Errorf("something else ... "))
}

func TestKeepErrorType(t *testing.T) {
	mzb := getNotFoundError()
	if cae, ok := mzb.(*ErrNotFound); !ok {
		t.Errorf("Error type was lost in translation !!: %T, %s", cae, reflect.TypeOf(mzb).String())
	}

	mzb = getNotFoundErrorWithAnnotations()
	if cae, ok := mzb.(*ErrNotFound); !ok {
		t.Errorf("Error type was lost in translation !!: %T, %s", cae, reflect.TypeOf(mzb).String())
	}

	mzb = getNotFoundErrorWithAnnotationsAndConsequences()
	if cae, ok := mzb.(*ErrNotFound); !ok {
		t.Errorf("Error type was lost in translation !!: %T, %s", cae, reflect.TypeOf(mzb).String())
	}
}

func TestUncategorizedError(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logrus.SetOutput(w)

	err := func() error {
		return InconsistentError("")
	}()
	if err == nil {
		t.Fail()
	}

	if err != nil {
		logrus.Warn(err.Error())
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	tk := string(out)

	if !strings.Contains(tk, "uncategorized error occurred:") {
		t.Fail()
	}
}

func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

func TestRecursiveAnnotation(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := &ErrNotFound{nil}
		err.Annotate("key", "value")
	}()
	failed := waitTimeout(&wg, 1*time.Second)
	if failed { // It never ended
		t.FailNow()
	}
}

func TestNotUncategorizedError(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logrus.SetOutput(w)

	err := func() error {
		return InconsistentError("something")
	}()
	if err == nil {
		t.Fail()
	}

	if err != nil {
		logrus.Warn(err.Error())
	}

	_ = w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	tk := string(out)

	if strings.Contains(tk, "uncategorized error occurred:") {
		t.Fail()
	}
	if !strings.Contains(tk, "something") {
		t.Fail()
	}
}

// typos adding consequences -> infinite loops
func TestNiceLoop(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		aerr := AbortedError(fmt.Errorf("this broke my heart"))
		_ = aerr.AddConsequence(aerr)

		broken := aerr.Error() // It works until we make the call
		_ = broken
	}()
	failed := waitTimeout(&wg, 500*time.Millisecond)
	if failed { // It never ended
		t.FailNow()
	}
}

func TestHelperCauseFunction(t *testing.T) {
	aerr := AbortedError(fmt.Errorf("this was painful: %w", fmt.Errorf("this broke my heart")))
	directCause := aerr.Cause()
	indirectCause := Cause(aerr)

	assert.EqualValues(t, directCause, indirectCause)
}

func TestHelperRootCauseFunction(t *testing.T) {
	aerr := AbortedError(fmt.Errorf("this was painful: %w", fmt.Errorf("this broke my heart")))
	directCause := aerr.RootCause()
	indirectCause := RootCause(aerr)

	assert.EqualValues(t, directCause, indirectCause)
}

func TestLastUnwrap(t *testing.T) {
	aerr := AbortedError(fmt.Errorf("this was painful: %w", fmt.Errorf("this broke my heart")))
	recovered := lastUnwrap(aerr)
	indirectRecovered := RootCause(aerr)

	assert.EqualValues(t, recovered, indirectRecovered)

	recovered = lastUnwrapOrNil(aerr)
	assert.EqualValues(t, recovered, indirectRecovered)
}

func TestLastUnwrapOrNil(t *testing.T) {
	aerr := AbortedError(nil, "why is so complicated ?")
	recovered := lastUnwrap(aerr)
	indirectRecovered := RootCause(aerr)
	assert.NotNil(t, indirectRecovered)
	assert.NotNil(t, recovered)

	assert.EqualValues(t, recovered, indirectRecovered)

	recovered = lastUnwrapOrNil(aerr)
	assert.Nil(t, recovered)
}

func TestPrettyPrintChainOfWrappedErrors(t *testing.T) {
	origin := NewError("It was DNS")
	toe := TimeoutError(origin, 100*time.Millisecond, "we tried to connect to google and we failed")
	dbe := Wrap(toe, "we failed internet connection (aka ping google) check")
	dba := Wrap(dbe, "the database failed some health checks")
	_ = dba.AddConsequence(NewError("The app failed to start"))

	formatted := dba.Error()
	if !strings.Contains(formatted, "the database failed some health checks: we failed internet connection (aka ping google) check: we tried to connect to google and we failed (timeout: 100ms): It was DNS") {
		t.Error("the formatting is wrong")
	}
	if !strings.Contains(formatted, "The app failed to start") {
		t.Error("the consequence formatting is wrong")
	}
}

func TestPrettyPrintErrorWithExtraInformation(t *testing.T) {
	origin := NewError("It was DNS")
	toe := TimeoutError(origin, 100*time.Millisecond, "we tried to connect to google and we failed")
	formatted := toe.Error()
	if !strings.Contains(formatted, "we tried to connect to google and we failed (timeout: 100ms): It was DNS") {
		t.Errorf("the formatting is wrong: %s", formatted)
	}
	if !strings.Contains(formatted, "100") {
		t.Errorf("we just lost information: %s", formatted)
	}
}

func TestNilCheckCast(t *testing.T) {
	var origin Error
	origin = generateErrTimeout()
	if _, ok := origin.(*ErrTimeout); !ok {
		t.Error("Must NOT happen")
	}
}

type checkable interface {
	IsNull() bool
}

func TestNotNilCheckCast(t *testing.T) {
	defer func() {
		if a := recover(); a != nil {
			t.Errorf("We panicked, this is a serious problem, it means that when we check for nil in our errors, we might be wrong")
		}
	}()

	var origin Error
	origin = generateErrNilTimeout()

	var nilErrTimeout *ErrTimeout = nil
	if origin != nil {
		if origin == nilErrTimeout { // nil and nilErrTimeout, are not the same
			t.Logf("a nil that is not interpreted as a nil, calling origin.whatever actually panics, put it to the test")
			_ = origin.GRPCCode()
		}
	}

	/*
		if origin != nil {
			if _, ok := origin.(*ErrTimeout); !ok || origin.IsNull() {
				t.Log("So far so good")
			} else {
				t.Errorf("Should not happen")
			}
		}
	*/
}

func TestNotNilCheckCastNoProblems(t *testing.T) {
	defer func() {
		if a := recover(); a != nil {
			t.Errorf("We panicked, this is a serious problem, it means that when we check for nil in our errors, we might be wrong")
		}
	}()

	var origin Error
	origin = noProblems()

	var nilErrTimeout *ErrTimeout = nil
	if origin != nil {
		if origin == nilErrTimeout { // nil and nilErrTimeout, are not the same
			t.Logf("a nil that is not interpreted as a nil, calling origin.whatever actually panics, put it to the test")
			_ = origin.GRPCCode()
		}
	}

	/*
		if origin != nil {
			if _, ok := origin.(*ErrTimeout); !ok || origin.IsNull() {
				t.Log("So far so good")
			} else {
				t.Errorf("Should not happen")
			}
		}
	*/
}

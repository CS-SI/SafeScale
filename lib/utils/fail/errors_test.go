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
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestInterfaceMatching(t *testing.T) {
	var ok bool

	{
		val := AbortedError(nil)
		_, ok = interface{}(val).(Error)
		assert.True(t, ok)
		_, ok = interface{}(val).(error)
		assert.True(t, ok)

		casted := val.(ErrAborted)
		_, ok = interface{}(casted).(Error)
		assert.True(t, ok)
		_, ok = interface{}(casted).(error)
		assert.True(t, ok)
	}

	{
		val := DuplicateError()
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplDuplicate doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplDuplicate doesn't satisfy interface error")
		}
		casted := val.(ErrDuplicate)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrDuplicate doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrDuplicate doesn't satisfy interface error")
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
		casted := val.(ErrorList)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrorList doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrorList doesn't satisfy interface error")
		}
	}

	{
		val := ForbiddenError()
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplForbidden doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplForbidden doesn't satisfy interface error")
		}
		casted := val.(ErrForbidden)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrForbidden doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrForbidden doesn't satisfy interface error")
		}
	}

	{
		val := InconsistentError()
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplInconsistent doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplInconsistent doesn't satisfy interface error")
		}
		casted := val.(ErrInconsistent)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrInconsistent doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrInconsistent doesn't satisfy interface error")
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
		casted := val.(ErrInvalidInstance)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrInvalidInstance doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrInvalidInstance doesn't satisfy interface error")
		}
	}

	{
		val := InvalidInstanceContentError("", "")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplInvalidInstanceContent doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplInvalidInstanceContent doesn't satisfy interface error")
		}
		casted := val.(ErrInvalidInstanceContent)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrInvalidInstanceContent doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrInvalidInstanceContent doesn't satisfy interface error")
		}
	}

	{
		val := InvalidParameterError("", "")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplInvalidParameter doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplInvalidParameter doesn't satisfy interface error")
		}
		casted := val.(ErrInvalidParameter)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrInvalidParameter doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrInvalidParameter doesn't satisfy interface error")
		}
	}

	{
		val := InvalidRequestError()
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplInvalidRequest doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplInvalidRequest doesn't satisfy interface error")
		}
		casted := val.(ErrInvalidRequest)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrInvalidRequest doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrInvalidRequest doesn't satisfy interface error")
		}
	}

	{
		val := NotAuthenticatedError()
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplNotAuthenticated doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplNotAuthenticated doesn't satisfy interface error")
		}
		casted := val.(ErrNotAuthenticated)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrNotAuthenticated doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrNotAuthenticated doesn't satisfy interface error")
		}
	}

	{
		val := NotAvailableError()
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplNotAvailable doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplNotAvailable doesn't satisfy interface error")
		}
		casted := val.(ErrNotAvailable)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrNotAvailable doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrNotAvailable doesn't satisfy interface error")
		}
	}

	{
		val := NotFoundError("")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplNotFound doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplNotFound doesn't satisfy interface error")
		}
		casted := val.(ErrNotFound)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrNotFound doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrNotFound doesn't satisfy interface error")
		}
	}

	{
		val := NotImplementedError("")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplNotImplemented doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplNotImplemented doesn't satisfy interface error")
		}
		casted := val.(ErrNotImplemented)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrNotImplemented doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrNotImplemented doesn't satisfy interface error")
		}
	}

	{
		val := OverflowError(nil, 1)
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplOverflow doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplOverflow doesn't satisfy interface error")
		}
		casted := val.(ErrOverflow)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrOverflow doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrOverflow doesn't satisfy interface error")
		}
	}

	{
		val := OverloadError("")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplOverload doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplOverload doesn't satisfy interface error")
		}
		casted := val.(ErrOverload)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrOverload doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrOverload doesn't satisfy interface error")
		}
	}

	{
		val := RuntimePanicError("")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplRuntimePanic doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplRuntimePanic doesn't satisfy interface error")
		}
		casted := val.(ErrRuntimePanic)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrRuntimePanic doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrRuntimePanic doesn't satisfy interface error")
		}
	}

	{
		val := SyntaxError("")
		if _, ok := interface{}(val).(Error); !ok {
			logrus.Fatal("*ImplSyntax doesn't satisfy interface Error")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("*ImplSyntax doesn't satisfy interface error")
		}
		casted := val.(ErrSyntax)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrSyntax doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrSyntax doesn't satisfy interface error")
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
		casted := val.(ErrTimeout)
		if _, ok := interface{}(casted).(Error); !ok {
			logrus.Fatal("ErrTimeout doesn't satisfy interface Error")
		}
		if _, ok := interface{}(casted).(error); !ok {
			logrus.Fatal("ErrTimeout doesn't satisfy interface error")
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
	if !strings.Contains(errct, "master-x") {
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
	r.Annotate("node", "master-x").Annotate("provider", "OWH")
	return r
}

func getNotFoundErrorWithAnnotations() error {
	r := NotFoundError("We lost something !!")
	r.Annotate("node", "master-x").Annotate("provider", "OWH")
	return r
}

func getNotFoundErrorWithAnnotationsAndConsequences() error {
	nfe := NotFoundError("We lost something !!")
	nfe.Annotate("node", "master-x").Annotate("provider", "OWH")
	return AddConsequence(nfe, fmt.Errorf("something else ... "))
}

func TestKeepErrorType(t *testing.T) {
	mzb := getNotFoundError()
	if cae, ok := mzb.(ErrNotFound); !ok {
		t.Errorf("Error type was lost in translation !!: %T, %s", cae, reflect.TypeOf(mzb).String())
	}

	mzb = getNotFoundErrorWithAnnotations()
	if cae, ok := mzb.(ErrNotFound); !ok {
		t.Errorf("Error type was lost in translation !!: %T, %s", cae, reflect.TypeOf(mzb).String())
	}

	mzb = getNotFoundErrorWithAnnotationsAndConsequences()
	if cae, ok := mzb.(ErrNotFound); !ok {
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

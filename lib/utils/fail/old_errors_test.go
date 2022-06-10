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
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestAFailErrorIsAnError(t *testing.T) {
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
		_ = av.setCauseFormatter(
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

func TestConstructors(t *testing.T) {
	ha := fmt.Errorf("too late")

	hab := NewErrorWithCause(ha, "surprise")
	if hab.IsNull() {
		t.Fail()
	}

	hac := NewErrorWithCauseAndConsequences(ha, []error{ha}, "unexpected")
	if hac.IsNull() {
		t.Fail()
	}

	had := NotFoundErrorWithCause(ha, nil, "horror")
	if had.IsNull() {
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
	_ = e.setCauseFormatter(
		func(e Error) string {
			return "toto"
		})
}

func TestNilNormalUsage(t *testing.T) {
	av := generateErrNilTimeout()
	if av != nil {
		_ = av.setCauseFormatter(
			func(e Error) string {
				return "toto"
			})
	}
}

// this test breaks no matter what, the first line of setCauseFormatter being 'if e.isNull()' of 'if e == nil' makes no difference
func TestNilNormalUsageSkippingNilCheck(t *testing.T) {
	defer func() {
		if x := recover(); x == nil {
			t.Fail()
		}
	}()

	av := generateErrNilTimeout()
	_ = av.setCauseFormatter(
		func(e Error) string {
			return "toto"
		})
}

// this test breaks no matter what, the first line of setCauseFormatter being 'if e.isNull()' of 'if e == nil' makes no difference
func TestNilInternalUsageSkippingNilCheck(t *testing.T) {
	defer func() {
		if x := recover(); x != nil {
			t.Fail()
		}
	}()

	av := generateNilNewError()
	_ = av.setCauseFormatter(
		func(e Error) string {
			return "toto"
		})
}

func TestFromPointerUsage(t *testing.T) {
	av := generateErrTimeout()
	if av != nil {
		_ = av.setCauseFormatter(
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
	r := NotImplementedErrorWithCauseAndConsequences(nil, nil, "LazyDevsWithCaveat()", "API not ready")
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

func TestHumanNaturePrintChainOfWrappedErrors(t *testing.T) {
	origin := NewError("It was DNS")
	toe := TimeoutError(origin, 100*time.Millisecond, "we tried to connect to google and we failed")
	dba := Wrap(toe, "we failed internet connection (aka ping google) check")
	_ = dba.AddConsequence(NewError("The app failed to start"))

	formatted := dba.Error()
	if !strings.Contains(formatted, "we failed internet connection (aka ping google) check: we tried to connect to google and we failed (timeout: 100ms): It was DNS") {
		t.Error("the formatting is wrong")
		t.Error("We wanted: we failed internet connection (aka ping google) check: we tried to connect to google and we failed (timeout: 100ms): It was DNS")
		t.Errorf("We got: %s", formatted)
	}
	if !strings.Contains(formatted, "The app failed to start") {
		t.Error("the consequence formatting is wrong")
	}
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
		t.Error("We wanted: the database failed some health checks: we failed internet connection (aka ping google) check: we tried to connect to google and we failed (timeout: 100ms): It was DNS")
		t.Errorf("We got: %s", formatted)
	}
	if !strings.Contains(formatted, "The app failed to start") {
		t.Error("the consequence formatting is wrong")
	}
}

func TestAddSelf(t *testing.T) {
	origin := NewError("It was DNS")
	toe := TimeoutError(origin, 100*time.Millisecond, "we tried to connect to google and we failed")
	tob := toe.AddConsequence(toe)

	assert.EqualValues(t, toe, tob)
	assert.True(t, len(toe.Consequences()) == 0)
}

func TestAddWrappedSelf(t *testing.T) {
	origin := NewError("It was DNS")
	toe := TimeoutError(origin, 100*time.Millisecond, "we tried to connect to google and we failed")
	tob := toe.AddConsequence(Wrap(toe, "meaningless info"))

	assert.EqualValues(t, toe, tob)
	assert.True(t, len(toe.Consequences()) == 0)
	assert.True(t, len(tob.Consequences()) == 0)
}

func TestAddWrappedCustomSelf(t *testing.T) {
	origin := NewError("It was DNS")
	toe := TimeoutError(origin, 100*time.Millisecond, "we tried to connect to google and we failed")
	tob := toe.AddConsequence(fmt.Errorf("meaningless info: %w", toe))

	assert.EqualValues(t, toe, tob)
	assert.True(t, len(toe.Consequences()) == 0)
	assert.True(t, len(tob.Consequences()) == 0)
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
	var origin Error = generateErrTimeout() //nolint
	if _, ok := origin.(*ErrTimeout); !ok {
		t.Error("Must NOT happen")
	}
}

func TestNotNilCheckCast(t *testing.T) {
	// typed nil issues
	defer func() {
		if a := recover(); a != nil {
			t.Logf("We panicked, this is a serious problem, it means that when we check for nil in our errors, we might be wrong")
		}
	}()

	var origin Error = generateErrNilTimeout() // nolint
	var nilErrTimeout *ErrTimeout = nil
	if origin != nil { // working with pointers to interfaces is dangerous, here we misinterpret origin as not nil (but it is) // nolint
		if origin == nilErrTimeout { // nil and nilErrTimeout, are not the same, the type matters, here we detect that actually is a nil, and we force the panic to prove the point
			t.Logf("a nil that is not interpreted as a nil, calling origin.whatever actually panics, put it to the test")
			_ = origin.Error()
			t.FailNow() // we won't reach this line
		}
		t.FailNow()
	} else {
		t.FailNow()
	}
}

func TestNotNilCheckCastNoProblems(t *testing.T) {
	// typed nil issues
	defer func() {
		if a := recover(); a != nil {
			t.Errorf("We panicked, this is a serious problem, it means that when we check for nil in our errors, we might be wrong")
		}
	}()

	var origin Error = noProblems() //nolint
	var nilErrTimeout *ErrTimeout = nil
	if origin != nil { // this test work well, when we return something that is NOT a pointer to an interface, no problems...
		if origin == nilErrTimeout { // nil and nilErrTimeout, are not the same
			t.Logf("a nil that is not interpreted as a nil, calling origin.whatever actually panics, put it to the test")
			_ = origin.Error()
		}
		t.FailNow()
	}
}

func TestAlteredNothing(t *testing.T) {
	var panicked error
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer OnPanic(&panicked)
		// Work with a nil value
		var an ErrAlteredNothing
		require.True(t, an.IsNull())

		_ = an.AddConsequence(fmt.Errorf("something"))

		txt := an.UnformattedError()
		require.EqualValues(t, txt, "")

		_ = an.Annotate("key", "value")

		_ = an.getGRPCCode()
	}()
	failed := waitTimeout(&wg, 1*time.Second)
	if failed && panicked == nil { // It never ended
		t.FailNow()
	}
}

func TestValidation(t *testing.T) {
	down := NewError("might be so")
	require.True(t, down.Valid())

	dj := errorCore{grpcCode: 28, lock: &sync.RWMutex{}}
	require.False(t, dj.Valid())

	mello := errorCore{grpcCode: 11}
	require.False(t, mello.Valid())
}

func up() {
	to()
}

func to() {
	var value error

	// meh
	// panic("made my mind") // here is the panic, we expect old_errors_test.go:799, period
	fmt.Println(value.Error())
}

func to2() {
	panic("made my mind") // this is the other panic, we expect old_errors_test.go:803, period
}

func up2() {
	to2()
}

func TestPanicLogs(t *testing.T) {
	var err error
	defer func() {
		if err != nil {
			fmt.Println("The perfect creatures: " + err.Error())
			if !strings.Contains(err.Error(), `panicked: in function github.com/CS-SI/SafeScale/v22/lib/utils/fail.to():  [.../lib/utils/fail/old_errors_test.go:799`) {
				if !strings.Contains(err.Error(), `panicked: in function github.com/CS-SI/SafeScale/v22/lib/utils/fail.to()`) && !strings.Contains(err.Error(), `lib/utils/fail/old_errors_test.go:799`) {
					t.Errorf("Bad content")
					t.FailNow()
				}
			}
		} else {
			t.Errorf("Nil error")
			t.FailNow()
		}
	}()
	defer OnPanic(&err)
	to()
}

func TestPanicLogsPlayed(t *testing.T) {
	var err error = fmt.Errorf("disaster")
	defer func() {
		if err != nil {
			fmt.Println("The perfect creatures: " + err.Error())
			if !strings.Contains(err.Error(), `panicked: in function github.com/CS-SI/SafeScale/v22/lib/utils/fail.to():  [.../lib/utils/fail/old_errors_test.go:799`) {
				if !strings.Contains(err.Error(), `panicked: in function github.com/CS-SI/SafeScale/v22/lib/utils/fail.to()`) && !strings.Contains(err.Error(), `lib/utils/fail/old_errors_test.go:799`) {
					t.Errorf("Bad content")
					t.FailNow()
				}
			}
		} else {
			t.Errorf("Nil error")
			t.FailNow()
		}
	}()
	defer OnPanic(&err)
	to()
}

func TestPanicLogsBis(t *testing.T) {
	var err Error
	defer func() {
		if err != nil {
			fmt.Println("The perfect creatures: " + err.Error())
			if !strings.Contains(err.Error(), `panicked: in function github.com/CS-SI/SafeScale/v22/lib/utils/fail.to():  [.../lib/utils/fail/old_errors_test.go:799`) {
				if !strings.Contains(err.Error(), `panicked: in function github.com/CS-SI/SafeScale/v22/lib/utils/fail.to()`) && !strings.Contains(err.Error(), `lib/utils/fail/old_errors_test.go:799`) {
					t.Errorf("Bad content")
					t.FailNow()
				}
			}
		} else {
			t.Errorf("Nil error")
			t.FailNow()
		}
	}()
	defer OnPanic(&err)
	to()
}

func TestPanicLogsBisPlayed(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	logrus.SetOutput(w)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err *ErrNotFound = NotFoundErrorWithCause(nil, nil, "disaster")
		defer func() {
			if err != nil {
				fmt.Println("The perfect creatures: " + err.Error())
			}
		}()
		defer OnPanic(err)
		to()
	}()
	failed := waitTimeout(&wg, 1500*time.Millisecond)
	if failed { // It never ended
		t.FailNow()
	}

	_ = w.Close()
	mehBytes, err := ioutil.ReadAll(r)
	if err != nil {
		t.FailNow()
	}
	os.Stdout = rescueStdout
	logrus.SetOutput(os.Stdout)

	meh := string(mehBytes)
	if !strings.Contains(meh, "fail.OnPanic()") {
		t.FailNow()
	}
	if !strings.Contains(meh, "coding mistake") {
		t.FailNow()
	}
}

func TestPanicBizarro(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	logrus.SetOutput(w)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err string
		defer OnPanic(&err)
		to()
	}()
	failed := waitTimeout(&wg, 1500*time.Millisecond)
	if failed { // It never ended
		t.FailNow()
	}

	_ = w.Close()
	mehBytes, err := ioutil.ReadAll(r)
	if err != nil {
		t.FailNow()
	}
	os.Stdout = rescueStdout
	logrus.SetOutput(os.Stdout)

	meh := string(mehBytes)
	if !strings.Contains(meh, "is invalid") {
		t.Error(meh)
		t.FailNow()
	}
	if !strings.Contains(meh, "unexpected type '*string'") {
		t.Error(meh)
		t.FailNow()
	}
}

func TestPanicBizarroButCleaner(t *testing.T) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	logrus.SetOutput(w)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err string
		defer OnPanic(&err)
		to()
	}()
	failed := waitTimeout(&wg, 1500*time.Millisecond)
	if failed { // It never ended
		t.FailNow()
	}

	_ = w.Close()
	mehBytes, err := ioutil.ReadAll(r)
	if err != nil {
		t.FailNow()
	}
	os.Stdout = rescueStdout
	logrus.SetOutput(os.Stdout)

	meh := string(mehBytes)
	if !strings.Contains(meh, "is invalid") {
		t.FailNow()
	}
	if !strings.Contains(meh, "unexpected type '*string'") {
		t.FailNow()
	}
}

func TestPanicLogsAlt(t *testing.T) {
	var err error
	defer func() {
		if err != nil {
			fmt.Println("The perfect creatures: " + err.Error())
			if !strings.Contains(err.Error(), `panicked: in function github.com/CS-SI/SafeScale/v22/lib/utils/fail.to():  [.../lib/utils/fail/old_errors_test.go:794`) {
				if !strings.Contains(err.Error(), `panicked: in function github.com/CS-SI/SafeScale/v22/lib/utils/fail.to()`) && !strings.Contains(err.Error(), `lib/utils/fail/old_errors_test.go:794`) {
					t.Errorf("Bad content")
					t.FailNow()
				}
			}
		} else {
			t.Errorf("Nil error")
			t.FailNow()
		}
	}()
	defer OnPanic(&err)
	up2()
}

func TestPanicLogsPlayedAlt(t *testing.T) {
	var err error = fmt.Errorf("disaster")
	defer func() {
		if err != nil {
			fmt.Println("The perfect creatures: " + err.Error())
			if !strings.Contains(err.Error(), `panicked: in function github.com/CS-SI/SafeScale/v22/lib/utils/fail.to():  [.../lib/utils/fail/old_errors_test.go:794`) {
				if !strings.Contains(err.Error(), `panicked: in function github.com/CS-SI/SafeScale/v22/lib/utils/fail.to()`) && !strings.Contains(err.Error(), `lib/utils/fail/old_errors_test.go:794`) {
					t.Errorf("Bad content")
					t.FailNow()
				}
			}
		} else {
			t.Errorf("Nil error")
			t.FailNow()
		}
	}()
	defer OnPanic(&err)
	up2()
}

func TestPanicLogsBisAlt(t *testing.T) {
	var err Error
	defer func() {
		if err != nil {
			fmt.Println("The perfect creatures: " + err.Error())
			if !strings.Contains(err.Error(), `panicked: in function github.com/CS-SI/SafeScale/v22/lib/utils/fail.to():  [.../lib/utils/fail/old_errors_test.go:794`) {
				if !strings.Contains(err.Error(), `panicked: in function github.com/CS-SI/SafeScale/v22/lib/utils/fail.to()`) && !strings.Contains(err.Error(), `lib/utils/fail/old_errors_test.go:794`) {
					t.Errorf("Bad content")
					t.FailNow()
				}
			}
		} else {
			t.Errorf("Nil error")
			t.FailNow()
		}
	}()
	defer OnPanic(&err)
	up2()
}

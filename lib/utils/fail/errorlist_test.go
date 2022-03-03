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
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_NewErrorList(t *testing.T) {

	errs := []error{}
	list := NewErrorList(errs)

	require.EqualValues(t, reflect.TypeOf(list).String(), "*fail.ErrorList")
	errs = []error{errors.New("math: square root of negative number")}
	list = NewErrorList(errs)

	require.EqualValues(t, len(list.(*ErrorList).errors), 1)

}

func TestNewErrorList_ToGRPCStatus(t *testing.T) {

	errs := NewErrorList([]error{errors.New("math: square root of negative number"), errors.New("can't resolve equation")})
	err := errs.ToGRPCStatus()

	require.EqualValues(t, reflect.TypeOf(err).String(), "*status.Error")
	require.NotEqual(t, strings.Index(err.Error(), "math: square root of negative number"), -1)
	require.NotEqual(t, strings.Index(err.Error(), "can't resolve equation"), -1)

}

func TestErrorList_AddConsequence(t *testing.T) {

	var errs *ErrorList = nil
	err := errs.AddConsequence(errors.New("math: square root of negative number"))
	if err == nil {
		t.Error("Can't AddConsequence to nil pointer ErrorList")
		t.Fail()
	}
	errv := NewErrorList([]error{})
	err = errv.AddConsequence(errv)
	require.EqualValues(t, fmt.Sprintf("%p", errv), fmt.Sprintf("%p", err))

	errv = NewErrorList([]error{})
	err = errv.AddConsequence(errors.New("math: square root of negative number"))
	if err == nil {
		t.Error("Can't AddConsequence to empty ErrorList")
		t.Fail()
	}

	errv = NewErrorList([]error{errors.New("math: square root of negative number"), errors.New("can't resolve equation")})
	err = errv.AddConsequence(errors.New("can't resolve equation"))
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrorList")

}

func TestErrorList_Annotate(t *testing.T) {

	defer func() {
		if r := recover(); r != nil {
			t.Error("Unexpected panic ", r)
			t.Fail()
		}
	}()

	var errs *ErrorList = nil
	errs.Annotate("stdout", os.Stdout)

	errv := NewErrorList([]error{})
	errv.Annotate("stdout", os.Stdout)

	errk := NewErrorList([]error{errors.New("math: square root of negative number"), errors.New("can't resolve equation")})
	errk.Annotate("stdout", os.Stdout)

	require.EqualValues(t, reflect.TypeOf(errk).String(), "*fail.ErrorList")

	require.NotEqual(t, strings.Index(errk.Error(), "math: square root of negative number"), -1)
	require.NotEqual(t, strings.Index(errk.Error(), "can't resolve equation"), -1)

}

func TestErrorList_Error(t *testing.T) {

	defer func() {
		if r := recover(); r != nil {
			t.Error("Unexpected panic ", r)
			t.Fail()
		}
	}()

	var errs *ErrorList = nil
	serr := errs.Error()
	require.EqualValues(t, serr, "")

	errv := NewErrorList([]error{})
	serr = errv.Error()
	require.EqualValues(t, serr, "")

	errk := NewErrorList([]error{errors.New("math: square root of negative number"), errors.New("can't resolve equation")})
	serr = errk.Error()

	require.NotEqual(t, strings.Index(serr, "math: square root of negative number"), -1)
	require.NotEqual(t, strings.Index(serr, "can't resolve equation"), -1)

}

func TestErrorList_UnformattedError(t *testing.T) {

	defer func() {
		if r := recover(); r != nil {
			t.Error("Unexpected panic ", r)
			t.Fail()
		}
	}()

	var errs *ErrorList = nil
	serr := errs.UnformattedError()
	require.EqualValues(t, serr, "")

	errv := NewErrorList([]error{})
	serr = errv.UnformattedError()
	require.EqualValues(t, serr, "")

	errk := NewErrorList([]error{errors.New("math: square root of negative number"), errors.New("can't resolve equation")})
	serr = errk.UnformattedError()

	require.NotEqual(t, strings.Index(serr, "math: square root of negative number"), -1)
	require.NotEqual(t, strings.Index(serr, "can't resolve equation"), -1)

}

func TestErrorList_ToErrorSlice(t *testing.T) {

	defer func() {
		if r := recover(); r != nil {
			t.Error("Unexpected panic ", r)
			t.Fail()
		}
	}()
	var errs *ErrorList = nil
	serr := errs.ToErrorSlice()
	require.EqualValues(t, len(serr), 0)

	errv := NewErrorList([]error{}).(*ErrorList)
	serr = errv.ToErrorSlice()
	require.EqualValues(t, len(serr), 0)

	errk := NewErrorList([]error{errors.New("math: square root of negative number"), errors.New("can't resolve equation")}).(*ErrorList)
	serr = errk.ToErrorSlice()
	require.EqualValues(t, len(serr), 2)

}

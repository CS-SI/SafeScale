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
	"strings"
	"sync"
	"testing"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
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
		message:             "math: can't divide by zero",
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

func Test_IsGRPCTimeout(t *testing.T) {

}

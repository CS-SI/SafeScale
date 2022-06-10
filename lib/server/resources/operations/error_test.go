//go:build ut
// +build ut

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

package operations

import (
	"errors"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

func Test_ActionFromError(t *testing.T) {

	tests := [](struct {
		name string
		in   error
		out  string
	}){
		{
			name: "from AbortedError",
			in:   fail.AbortedError(errors.New("aborted error !")),
			out:  "abort",
		},
		{
			name: "from nil",
			in:   nil,
			out:  "",
		},
		{
			name: "from error",
			in:   errors.New("aborted error !"),
			out:  "failure",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret := ActionFromError(tt.in)
			require.EqualValues(t, ret, tt.out)
		})
	}
}

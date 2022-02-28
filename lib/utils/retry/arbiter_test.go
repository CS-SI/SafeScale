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

package retry

import (
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/retry/enums/verdict"
	"github.com/stretchr/testify/require"
)

func Test_OrArbiter(t *testing.T) {

	tests := []struct {
		arb    func(t Try) (verdict.Enum, fail.Error)
		expect verdict.Enum
	}{
		{
			arb: func(t Try) (verdict.Enum, fail.Error) {
				return verdict.Done, nil
			},
			expect: verdict.Done,
		},
		{
			arb: func(t Try) (verdict.Enum, fail.Error) {
				return verdict.Abort, nil
			},
			expect: verdict.Abort,
		},
		{
			arb: func(t Try) (verdict.Enum, fail.Error) {
				return verdict.Undecided, nil
			},
			expect: verdict.Retry,
		},
	}

	try := Try{}
	for i := range tests {
		result := OrArbiter(tests[i].arb)
		require.EqualValues(t, reflect.TypeOf(result).String(), "retry.Arbiter")
		a_verdict, err := result(try)
		require.EqualValues(t, err, nil)
		require.EqualValues(t, a_verdict, tests[i].expect)
	}

}

func Test_Max(t *testing.T) {

	func() {
		defer func() {
			r := recover()
			require.EqualValues(t, r, "invalid Max configuration")
		}()
		Max(0)
	}()

}

func Test_Min(t *testing.T) {

	func() {
		defer func() {
			r := recover()
			require.EqualValues(t, r, "invalid Min configuration")
		}()
		Min(0)
	}()

}

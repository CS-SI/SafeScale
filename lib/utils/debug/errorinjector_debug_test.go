//go:build debug
// +build debug

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

package debug

import (
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

func supernatural() fail.Error {
	return nil
}

func TestInjectPlannedFailWithProbability(t *testing.T) {
	err := setup("errorinjector_debug_test.go:23:p:1") // line 23 (the one with InjectPlannedFail, with probability 1 -> 100%)
	if err != nil {
		return
	}

	xerr := supernatural()
	xerr = InjectPlannedFail(xerr)
	if xerr == nil {
		t.FailNow()
	}
}

func TestInjectPlannedFailWithIteration(t *testing.T) {
	err := setup("errorinjector_debug_test.go:38:i:4") // line 38 (the one with InjectPlannedFail, iteration, after the 4th time, it always breaks)
	if err != nil {
		return
	}

	failures := 0
	for i := 0; i < 10; i++ {
		xerr := supernatural()
		xerr = InjectPlannedFail(xerr)
		if xerr == nil {
			failures += 1
			if i >= 3 { // 4h time until 10 -> 4..10
				t.Fail()
			}
		}
	}

	if failures != 3 {
		t.FailNow()
	}
}

func TestInjectPlannedFailOnceWithIteration(t *testing.T) {
	err := setup("errorinjector_debug_test.go:60:o:4") // line 60 (the one with InjectPlannedFail, iterating ONLY the 4th time breaks)
	if err != nil {
		return
	}

	for i := 0; i < 10; i++ {
		xerr := supernatural()
		xerr = InjectPlannedFail(xerr)
		if xerr != nil {
			if i != 3 { // 4th time -> 0..3
				t.Fail()
			}
		}
	}
}

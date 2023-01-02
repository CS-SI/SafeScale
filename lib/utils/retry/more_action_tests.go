//go:build alltests
// +build alltests

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

package retry

import (
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

func TestErrCheckStdError(t *testing.T) {
	iteration := 0
	xerr := WhileUnsuccessful(
		func() error {
			iteration++
			return fail.NewError("It failed at iteration #%d", iteration)
		},
		10*time.Millisecond,
		80*time.Millisecond,
	)
	if xerr != nil {
		xerr = fail.Wrap(xerr, "the checking failed")
		t.Logf(xerr.Error())
		if !(strings.Contains(xerr.Error(), "failed at iteration") && (strings.Contains(xerr.Error(), "#6") || strings.Contains(xerr.Error(), "#7") || strings.Contains(xerr.Error(), "#8") || strings.Contains(xerr.Error(), "#9"))) {
			t.FailNow()
		}
	}
}

func TestErrCheckStdErrorHard(t *testing.T) {
	iteration := 0
	xerr := WhileUnsuccessfulWithHardTimeout(
		func() error {
			iteration++
			return fail.NewError("It failed at iteration #%d", iteration)
		},
		10*time.Millisecond,
		80*time.Millisecond,
	)
	if xerr != nil {
		xerr = fail.Wrap(xerr, "the checking failed")
		t.Logf(xerr.Error())
		if !(strings.Contains(xerr.Error(), "failed at iteration") && (strings.Contains(xerr.Error(), "#6") || strings.Contains(xerr.Error(), "#7") || strings.Contains(xerr.Error(), "#8") || strings.Contains(xerr.Error(), "#9"))) {
			if !strings.Contains(xerr.Error(), "desist") {
				t.FailNow()
			}
		}
	}
}

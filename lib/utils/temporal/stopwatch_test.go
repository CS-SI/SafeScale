/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package temporal

import (
	"strings"
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	stowa := Stopwatch{}

	res := FormatDuration(stowa.Duration())
	if !strings.Contains(res, "00h00m00.001s") {
		t.Errorf("This should be 1 ms and it isn't: %s", res)
	}
}

func TestStopDuration(t *testing.T) {
	stowa := Stopwatch{}

	stowa.Stop()
	stowa.Stop()

	res := FormatDuration(stowa.Duration())
	if !strings.Contains(res, "00h00m00.001s") {
		t.Errorf("This should be 1 ms and it isn't: %s", res)
	}
}

func TestStartStopDuration(t *testing.T) {
	stowa := Stopwatch{}

	stowa.Start()
	time.Sleep(10 * time.Millisecond)
	stowa.Stop()

	res := FormatDuration(stowa.Duration())
	if !strings.Contains(res, "0.010s") {
		t.Errorf("This should be 10 ms and it isn't: %s", res)
	}
}

func TestStartStopDurationAgain(t *testing.T) {
	stowa := Stopwatch{}

	stowa.Start()
	time.Sleep(10 * time.Millisecond)
	stowa.Stop()
	time.Sleep(time.Second)
	stowa.Start()
	time.Sleep(20 * time.Millisecond)
	stowa.Start()
	stowa.Stop()

	res := FormatDuration(stowa.Duration())
	if !strings.Contains(res, "0.030 ms") {
		t.Errorf("This should be 30 ms and it isn't: %s", res)
	}
}

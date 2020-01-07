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

package temporal

import (
	"strings"
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	stowa := NewStopwatch()

	res := FormatDuration(stowa.Duration())
	if !strings.Contains(res, "00h00m00.001s") {
		t.Errorf("This should be 1 ms and it isn't: %s", res)
	}
}

func TestStopDuration(t *testing.T) {
	stowa := NewStopwatch()

	stowa.Stop()
	stowa.Stop()

	res := FormatDuration(stowa.Duration())
	if !strings.Contains(res, "00h00m00.001s") {
		t.Errorf("This should be 1 ms and it isn't: %s", res)
	}
}

func TestStartStopDuration(t *testing.T) {
	stowa := NewStopwatch()

	stowa.Start()
	time.Sleep(10 * time.Millisecond)
	stowa.Stop()

	res := FormatDuration(stowa.Duration())
	if !strings.Contains(res, "0.010s") {
		t.Errorf("This should be 10 ms and it isn't: %s", res)
	}
}

func TestStartStopDurationAgain(t *testing.T) {
	stowa := NewStopwatch()

	stowa.Start()
	time.Sleep(10 * time.Millisecond)
	stowa.Stop() // next calls won't change Duration because we used Stop instead of Pause

	time.Sleep(time.Second)
	stowa.Start()
	time.Sleep(20 * time.Millisecond)
	stowa.Stop()

	res := FormatDuration(stowa.Duration())
	if !strings.Contains(res, "0.010s") {
		t.Errorf("This should be 10 ms and it isn't: %s", res)
	}
}

func TestStartStopDurationWithPause(t *testing.T) {
	stowa := NewStopwatch()

	stowa.Start()
	time.Sleep(10 * time.Millisecond)
	stowa.Pause() // this time, duration changes because we used Pause

	time.Sleep(time.Second)
	stowa.Start()
	time.Sleep(20 * time.Millisecond)
	stowa.Stop()

	res := FormatDuration(stowa.Duration())
	if !strings.Contains(res, "0.030s") {
		t.Errorf("This should be 30 ms and it isn't: %s", res)
	}
}

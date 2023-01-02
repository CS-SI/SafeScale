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
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_Constant(t *testing.T) {

	var d time.Duration = -100
	got := Constant(d)
	require.EqualValues(t, reflect.TypeOf(got).String(), "*retry.Officer")

	d = 100 * time.Millisecond
	now := time.Now()
	got = Constant(d)
	got.Block(Try{})
	got.Block(Try{})
	got.Block(Try{})
	elapsed := time.Since(now)
	if elapsed <= 200*time.Millisecond && elapsed >= 400*time.Millisecond {
		t.Error("Out of expected duration bounds")
		t.Fail()
	}

}

func Test_Incremental(t *testing.T) {

	var d time.Duration = -100
	got := Incremental(d)
	require.EqualValues(t, reflect.TypeOf(got).String(), "*retry.Officer")

	d = 100 * time.Millisecond
	now := time.Now()
	got = Incremental(d)
	got.Block(Try{})
	got.Block(Try{})
	got.Block(Try{})
	elapsed := time.Since(now)
	if elapsed <= 200*time.Millisecond && elapsed >= 400*time.Millisecond {
		t.Error("Out of expected duration bounds")
		t.Fail()
	}

}

func Test_Linear(t *testing.T) {

	var d time.Duration = -100
	got := Linear(d)
	require.EqualValues(t, reflect.TypeOf(got).String(), "*retry.Officer")

	d = 100 * time.Millisecond
	now := time.Now()
	got = Linear(d)
	got.Block(Try{})
	got.Block(Try{})
	got.Block(Try{})
	elapsed := time.Since(now)
	if elapsed <= 30*time.Microsecond && elapsed >= 100*time.Millisecond {
		t.Error("Out of expected duration bounds")
		t.Fail()
	}

}

func Test_Exponential(t *testing.T) {

	var d time.Duration = -100
	got := Exponential(d)
	require.EqualValues(t, reflect.TypeOf(got).String(), "*retry.Officer")

	d = 100 * time.Millisecond
	now := time.Now()
	got = Exponential(d)
	got.Block(Try{})
	got.Block(Try{})
	got.Block(Try{})
	elapsed := time.Since(now)
	if elapsed <= 200*time.Millisecond && elapsed >= 350*time.Millisecond {
		t.Error("Out of expected duration bounds")
		t.Fail()
	}

}

func Test_Fibonacci(t *testing.T) {
	now := time.Now()
	got := Fibonacci(100 * time.Millisecond)
	got.Block(Try{}) // 100 +- 10
	got.Block(Try{}) // 200 +- 10
	got.Block(Try{}) // 300 +- 10
	got.Block(Try{}) // 500 +- 10
	elapsed := time.Since(now)
	if elapsed < 1000*time.Millisecond || elapsed > 1200*time.Millisecond {
		t.Errorf("this should have been 1100 +- 40 ms: %s", elapsed)
		t.FailNow()
	}
}

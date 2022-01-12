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

package server

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/gregoryv/gocyclo"
)

func complexityTester(maximum int, subdir string, t *testing.T) {
	files, err := filepath.Glob(fmt.Sprintf("./%s/*.go", subdir))
	if err != nil {
		t.Fatal(err)
	}

	max := maximum
	result, ok := gocyclo.Assert(files, max)
	if !ok {
		for _, l := range result {
			t.Log(l)
		}
		t.Errorf("Exceeded maximum complexity %v", max)
	}
}

func TestComplexity(t *testing.T) {
	// FIXME: In time, not a single subpackage complexity should be greater than 25

	complexityTester(20, "cluster", t)
	complexityTester(110, "handlers", t) // FIXME: Reduce complexity
	complexityTester(48, "iaas", t)      // FIXME: Reduce complexity
	complexityTester(51, "install", t)   // FIXME: Reduce complexity
	complexityTester(20, "listeners", t)
	complexityTester(20, "metadata", t)
	complexityTester(20, "utils", t)
}

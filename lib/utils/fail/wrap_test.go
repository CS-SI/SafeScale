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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnwrap(t *testing.T) {
	root := fmt.Errorf("to be both free and safe")
	leaf := Wrap(root, "it's beautiful")

	recovered := lastUnwrap(leaf)

	assert.EqualValues(t, recovered, root)
}

func TestUnwrapFmt(t *testing.T) {
	root := fmt.Errorf("to be both free and safe")
	leaf := fmt.Errorf("it's beautiful: %w", root)

	recovered := lastUnwrap(leaf)

	assert.EqualValues(t, root, recovered)
}

func TestRootCause(t *testing.T) {
	root := fmt.Errorf("to be both free and safe")
	leaf := Wrap(root, "it's beautiful")

	recovered := RootCause(leaf)

	assert.EqualValues(t, root, recovered)
}

func TestRootCauseFmt(t *testing.T) {
	root := fmt.Errorf("to be both free and safe")
	leaf := fmt.Errorf("it's beautiful: %w", root)

	recovered := RootCause(leaf)

	assert.EqualValues(t, root, recovered)
}

func TestCause(t *testing.T) {
	root := fmt.Errorf("to be both free and safe")
	leaf := Wrap(root, "it's beautiful")

	recovered := Cause(leaf)

	assert.EqualValues(t, root, recovered)
}

func TestCauseFmt(t *testing.T) {
	root := fmt.Errorf("to be both free and safe")
	leaf := fmt.Errorf("it's beautiful: %w", root)

	recovered := Cause(leaf)

	assert.EqualValues(t, root, recovered)
}

func TestCauseConvert(t *testing.T) {
	root := fmt.Errorf("to be both free and safe")
	leaf := Wrap(root, "it's beautiful")

	recovered := Cause(ConvertError(leaf))

	assert.EqualValues(t, root, recovered)
}

func TestCauseFmtConvert(t *testing.T) {
	root := fmt.Errorf("to be both free and safe")
	leaf := fmt.Errorf("it's beautiful: %w", root)

	recovered := Cause(ConvertError(leaf))

	assert.EqualValues(t, root, recovered)
}

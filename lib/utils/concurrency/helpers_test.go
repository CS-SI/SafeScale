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

package concurrency

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_randomIntWithReseed(t *testing.T) {
	a := randomIntWithReseed(0, 8000)
	assert.True(t, a < 8001)
	b := randomIntWithReseed(0, 8000)
	assert.True(t, b < 8001)
	c := randomIntWithReseed(0, 8000)
	assert.True(t, c < 8001)
}

func Test_outOfRangeTaskStatus(t *testing.T) {
	ta := TaskStatus(9)
	reprTa := ta.String()

	assert.NotNil(t, reprTa)
	assert.NotEmpty(t, reprTa)
	assert.True(t, strings.Contains(reprTa, "9"))

	ta = TaskStatus(2)
	reprTa = ta.String()
	assert.NotNil(t, reprTa)
	assert.NotEmpty(t, reprTa)
	assert.True(t, strings.Contains(reprTa, "RUNNING"))
}

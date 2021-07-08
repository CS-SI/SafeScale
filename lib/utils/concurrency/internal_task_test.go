/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInvalidInternalTaskCtx(t *testing.T) {
	ta, xerr := newTask(nil, nil)
	require.Nil(t, ta)
	require.NotNil(t, xerr)
}

func TestInternalChecks(t *testing.T) {
	ta, xerr := newTaskGroup(nil, nil) // It doesn't behave the same way newTask does, it should
	require.Nil(t, ta)
	require.NotNil(t, xerr)
}

/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package data

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type SomeData struct {
	Name string
}

func (sd *SomeData) IsNull() bool {
	return sd == nil || sd.Name == ""
}

func TestIsNull(t *testing.T) {
	v := &SomeData{}
	require.True(t, v.IsNull())

	v.Name = "data"
	require.False(t, v.IsNull())

	v = nil
	require.True(t, v.IsNull())
}

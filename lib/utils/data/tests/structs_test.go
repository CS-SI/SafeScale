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

package tests

import (
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/stretchr/testify/require"
)

func TestStructWithoutPointers_IsNull(t *testing.T) {

	var s *StructWithoutPointers
	require.EqualValues(t, s.IsNull(), true)
	s = &StructWithoutPointers{
		Content: "",
	}
	require.EqualValues(t, s.IsNull(), true)
	s = &StructWithoutPointers{
		Rumba: 0,
	}
	require.EqualValues(t, s.IsNull(), true)
	s = &StructWithoutPointers{
		Content: "Any",
	}
	require.EqualValues(t, s.IsNull(), false)
	s = &StructWithoutPointers{
		Rumba: 1,
	}
	require.EqualValues(t, s.IsNull(), false)

}

func TestStructWithPointersAndDefectiveReplace_IsNull(t *testing.T) {

	var s *StructWithPointersAndDefectiveReplace

	require.EqualValues(t, s.IsNull(), true)
	s = &StructWithPointersAndDefectiveReplace{
		Content: "",
	}
	require.EqualValues(t, s.IsNull(), true)
	s = &StructWithPointersAndDefectiveReplace{
		Rumba: 0,
	}
	require.EqualValues(t, s.IsNull(), true)
	s = &StructWithPointersAndDefectiveReplace{
		Content: "Any",
	}
	require.EqualValues(t, s.IsNull(), false)
	s = &StructWithPointersAndDefectiveReplace{
		Rumba: 1,
	}
	require.EqualValues(t, s.IsNull(), false)
	s = &StructWithPointersAndDefectiveReplace{
		List: []string{"Any"},
	}
	require.EqualValues(t, s.IsNull(), false)
	s = &StructWithPointersAndDefectiveReplace{
		Map: map[string]interface{}{
			"Any": "data",
		},
	}
	require.EqualValues(t, s.IsNull(), false)

}

func TestStructWithPointersAndCorrectReplace_IsNull(t *testing.T) {

	var s *StructWithPointersAndCorrectReplace

	require.EqualValues(t, s.IsNull(), true)
	s = &StructWithPointersAndCorrectReplace{
		content: "",
	}
	require.EqualValues(t, s.IsNull(), true)
	s = &StructWithPointersAndCorrectReplace{
		Rumba: 0,
	}
	require.EqualValues(t, s.IsNull(), true)
	s = &StructWithPointersAndCorrectReplace{
		content: "Any",
	}
	require.EqualValues(t, s.IsNull(), false)
	s = &StructWithPointersAndCorrectReplace{
		Rumba: 1,
	}
	require.EqualValues(t, s.IsNull(), false)
	s = &StructWithPointersAndCorrectReplace{
		List: []string{"Any"},
	}
	require.EqualValues(t, s.IsNull(), false)
	s = &StructWithPointersAndCorrectReplace{
		Map: map[string]interface{}{
			"Any": "data",
		},
	}
	require.EqualValues(t, s.IsNull(), false)

}

func TestStructWithPointersAndCorrectReplace_Replace(t *testing.T) {

	defer func() {
		r := recover()
		if r == nil {
			t.Error("Expect panic")
			t.Fail()
		}

	}()

	var s *StructWithPointersAndCorrectReplace
	var c data.Clonable
	_, _ = s.Replace(c)

}

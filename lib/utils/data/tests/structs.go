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

package tests

import (
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

type StructWithoutPointers struct {
	Content string
	Rumba   int
}

func NewStructWithoutPointers() *StructWithoutPointers {
	return &StructWithoutPointers{}
}

func (m *StructWithoutPointers) IsNull() bool {
	return m == nil || (m.Content == "" && m.Rumba == 0)
}

func (m StructWithoutPointers) Clone() data.Clonable {
	return NewStructWithoutPointers().Replace(&m)
}

func (m *StructWithoutPointers) Replace(clonable data.Clonable) data.Clonable {
	*m = *clonable.(*StructWithoutPointers)
	return m
}

type StructWithPointersAndDefectiveReplace struct {
	Content string
	Rumba   int
	List    []string
	Map     map[string]interface{}
}

func NewStructWithPointersAndDefectiveReplace() *StructWithPointersAndDefectiveReplace {
	return &StructWithPointersAndDefectiveReplace{}
}

func (m *StructWithPointersAndDefectiveReplace) IsNull() bool {
	return m == nil || (m.Content == "" && m.Rumba == 0 && len(m.List) == 0 && len(m.Map) == 0)
}

func (m StructWithPointersAndDefectiveReplace) Clone() data.Clonable {
	newM := &StructWithPointersAndDefectiveReplace{}
	newM.Replace(&m)
	return newM
}

func (m *StructWithPointersAndDefectiveReplace) Replace(clonable data.Clonable) data.Clonable {
	*m = *clonable.(*StructWithPointersAndDefectiveReplace)
	return m
}

type StructWithPointersAndCorrectReplace struct {
	content string
	Rumba   int
	List    []string
	Map     map[string]interface{}
}

func NewStructWithPointersAndCorrectReplace() *StructWithPointersAndCorrectReplace {
	return &StructWithPointersAndCorrectReplace{}
}

func (m *StructWithPointersAndCorrectReplace) IsNull() bool {
	return m == nil || (m.content == "" && m.Rumba == 0 && len(m.List) == 0 && len(m.Map) == 0)
}

func (m StructWithPointersAndCorrectReplace) Clone() data.Clonable {
	return NewStructWithPointersAndCorrectReplace().Replace(&m)
}

func (m *StructWithPointersAndCorrectReplace) Replace(clonable data.Clonable) data.Clonable {
	src := clonable.(*StructWithPointersAndCorrectReplace)

	// This part copies non-pointers values
	*m = *src

	// This parts duplicates values from pointers
	m.List = make([]string, len(src.List))
	copy(m.List, src.List)

	m.Map = make(map[string]interface{}, len(src.Map))
	for k, v := range src.Map {
		m.Map[k] = v
	}

	return m
}

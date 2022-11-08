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
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
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

func (m StructWithoutPointers) Clone() (clonable.Clonable, error) {
	n := NewStructWithoutPointers()
	return n, n.Replace(&m)
}

func (m *StructWithoutPointers) Replace(p clonable.Clonable) error {
	src, err := lang.Cast[*StructWithoutPointers](p)
	if err != nil {
		return fmt.Errorf("p is not a *StructWithoutPointers")
	}

	*m = *src
	return nil
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

func (m StructWithPointersAndDefectiveReplace) Clone() (clonable.Clonable, error) {
	newM := &StructWithPointersAndDefectiveReplace{}
	return newM, newM.Replace(&m)
}

func (m *StructWithPointersAndDefectiveReplace) Replace(p clonable.Clonable) error {
	src, err := lang.Cast[*StructWithPointersAndDefectiveReplace](p)
	if err != nil {
		return fmt.Errorf("p is not a *StructWithPointersAndDefectiveReplace")
	}

	*m = *src
	return nil
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

func (m StructWithPointersAndCorrectReplace) Clone() (clonable.Clonable, error) {
	nm := NewStructWithPointersAndCorrectReplace()
	return nm, nm.Replace(&m)
}

func (m *StructWithPointersAndCorrectReplace) Replace(p clonable.Clonable) error {
	src, err := lang.Cast[*StructWithPointersAndCorrectReplace](p)
	if err != nil {
		panic(err.Error())
	}

	// This part copies non-pointers values
	*m = *src

	// This parts duplicates values from pointers
	m.List = make([]string, len(src.List))
	copy(m.List, src.List)

	m.Map = make(map[string]interface{}, len(src.Map))
	for k, v := range src.Map {
		m.Map[k] = v
	}

	return nil
}

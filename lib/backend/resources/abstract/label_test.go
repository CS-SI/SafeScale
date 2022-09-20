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

package abstract

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type BrokenLabel struct {
	ID           string
	Name         string
	HasDefault   bool
	DefaultValue string
}

func NewBrokenLabel() *BrokenLabel                                    { return &BrokenLabel{HasDefault: true} }
func (t *BrokenLabel) IsNull() bool                                   { return false }
func (t *BrokenLabel) Clone() (data.Clonable, error)                  { return t, nil }
func (t *BrokenLabel) Replace(p data.Clonable) (data.Clonable, error) { return p, nil }
func (t *BrokenLabel) Valid() bool                                    { return false }
func (t BrokenLabel) OK() bool                                        { return true }
func (t *BrokenLabel) Serialize() ([]byte, fail.Error) {
	return nil, fail.ConvertError(fmt.Errorf("I'm broken!"))
}
func (t *BrokenLabel) Deserialize(buf []byte) (ferr fail.Error) {
	return fail.ConvertError(fmt.Errorf("I'm broken!"))
}
func (t *BrokenLabel) GetName() string        { return "broken!" }
func (t *BrokenLabel) GetID() (string, error) { return "broken", nil }
func (t *BrokenLabel) IsTag() bool            { return false }

func TestLabel_NewLabel(t *testing.T) {

	s := NewLabel()
	if !s.IsNull() {
		t.Error("Label is null")
		t.Fail()
	}
	if s.OK() {
		t.Error("Label is ok")
		t.Fail()
	}
	s.ID = "Label ID"
	s.Name = "Label Name"
	if s.IsNull() {
		t.Error("Label is not null")
		t.Fail()
	}
	if !s.OK() {
		t.Error("Label is not ok!")
		t.Fail()
	}

}

func TestLabel_IsNull(t *testing.T) {
	var s *Label = nil
	if !s.IsNull() {
		t.Error("Nil pointer Label must be null")
		t.Fail()
	}
	s = NewLabel()
	if !s.IsNull() {
		t.Error("Label without ID or Name must be null")
		t.Fail()
	}
	s.ID = "Label ID"
	if s.OK() {
		t.Error("Label with ID but no Name must not be valid")
		t.Fail()
	}
	if s.IsNull() {
		t.Error("Label with ID but no Name must not be null")
		t.Fail()
	}
	s.ID = ""
	s.Name = "Label Name"
	if s.OK() {
		t.Error("Label with Name but no ID must not be valid")
		t.Fail()
	}
	if s.IsNull() {
		t.Error("Label with Name but no ID must not be null")
		t.Fail()
	}
	s.ID = "Label ID"
	if !s.OK() {
		t.Error("Label with Name and ID must be valid")
		t.Fail()
	}
	if s.IsNull() {
		t.Error("Label with Name and ID must not be null")
		t.Fail()
	}
}

func TestLabel_Replace(t *testing.T) {

	var s *Label = nil
	replaced, err := s.Replace(NewLabel())
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, replaced)

	s = NewLabel()
	replaced, err = s.Replace(nil)
	require.Nil(t, replaced)
	require.Contains(t, err.Error(), "invalid parameter: p")

	replaced, err = s.Replace(NewBrokenLabel())
	require.Nil(t, replaced)
	require.Contains(t, err.Error(), "p is not a *Label")

}

func TestLabel_Clone(t *testing.T) {
	s := NewLabel()
	s.ID = "Label ID"
	s.Name = "Label Name"

	at, err := s.Clone()
	if err != nil {
		t.Error(err)
	}

	sc, ok := at.(*Label)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, s, sc)
	require.EqualValues(t, s, sc)

	sc.Name = "Label Name changed"
	areEqual := reflect.DeepEqual(s, sc)
	if areEqual {
		t.Error("It's a shallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, s, sc)
}

func TestLabel_Serialize(t *testing.T) {

	var s *Label = nil
	serial, err := s.Serialize()
	if err == nil {
		t.Error("Can't serialize nil pointer")
		t.Fail()
	}

	s = NewLabel()
	s.ID = "Label ID"
	s.Name = "Label Name"
	serial, err = s.Serialize()
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	s2 := NewLabel()
	err = s2.Deserialize(serial)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	areEqual := reflect.DeepEqual(s, s2)
	if !areEqual {
		t.Error("Serialize/Deserialize does not restore values")
		t.Fail()
	}

}

func TestLabel_Deserialize(t *testing.T) {

	serial := []byte(`{"id": "Label ID","name":"Label Name"},"has_default":true,default_value":"toto"`)
	var s *Label = nil
	err := s.Deserialize(serial)
	if err == nil {
		t.Error("Can't deserialize to nil pointer")
		t.Fail()
	}

}

func TestLabel_GetName(t *testing.T) {
	s := NewLabel()
	s.Name = "Label Name"
	name := s.GetName()
	if name != s.Name {
		t.Error("Wrong value restitution")
		t.Fail()
	}
}

func TestLabel_GetID(t *testing.T) {

	var s *Label = nil
	id, err := s.GetID()
	require.EqualValues(t, id, "")
	require.Contains(t, err.Error(), "invalid instance")

	s = NewLabel()
	s.ID = "Label ID"
	id, _ = s.GetID()
	if id != s.ID {
		t.Error("Wrong value restitution")
		t.Fail()
	}
}

func TestLabel_IsTag(t *testing.T) {

	var s *Label = nil
	b := s.IsTag()
	require.False(t, b)

	s = NewLabel()
	s.HasDefault = true
	b = s.IsTag()
	require.True(t, b)

	s.HasDefault = false
	b = s.IsTag()
	require.False(t, b)

}

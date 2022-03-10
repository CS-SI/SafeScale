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

package data

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
	"github.com/stretchr/testify/require"
)

type SomeData struct {
	Name string
}

func (sd *SomeData) IsNull() bool {
	return sd == nil
}

func TestIsNull(t *testing.T) {
	v := &SomeData{}
	require.False(t, v.IsNull())

	v.Name = "data"
	require.False(t, v.IsNull())

	v = nil
	//goland:noinspection GoNilness
	require.True(t, v.IsNull())
}

// This test shows how the new IsNil or IsNull method handles correctly nil values
func TestIsNilIsGoodEnough(t *testing.T) {
	// what changes is the forget function, how we test the validity of thing, here is with the new IsNil method
	forget := func(thing NullValue) error {
		if !valid.IsNil(thing) {
			if _, ok := thing.(NullValue); ok {
				return nil
			}
			return nil
		}

		return fmt.Errorf("it was a nil")
	}

	// this code is the same for everyone
	var buried NullValue
	err := forget(buried)
	if err == nil {
		t.Error(err)
	}
	if !strings.Contains(err.Error(), "was a nil") {
		t.FailNow()
	}
}

// This test shows how the .IsNull method might panic, so it's not safe enough to protect us against nilness
func TestIsNullMethodIsNotGoodEnough(t *testing.T) {
	// what changes is the forget function, how we test the validity of thing, here is with the old .IsNull struct member function
	forget := func(thing NullValue) (crash error) {
		defer func(in *error) {
			harder := recover()
			if harder != nil {
				*in = fmt.Errorf("bad things happened")
			}
		}(&crash)

		if !thing.IsNull() {
			if _, ok := thing.(NullValue); ok {
				return nil
			}
			return nil
		}

		return fmt.Errorf("it was a nil")
	}

	// this code is the same for everyone
	var buried NullValue
	err := forget(buried)
	if err == nil {
		t.Error(err)
	}
	if !strings.Contains(err.Error(), "bad things") {
		t.FailNow()
	}
}

// This test shows how == nil first, then the .IsNull works, but remember that .IsNull was born because we didn't want to do the == nil, so .IsNull can be considered a failure in this regard
func TestEqualNilAndIsNullMethodIsGoodEnough(t *testing.T) {
	// what changes is the forget function, how we test the validity of thing, here is with != first, then with the old .IsNull struct member function
	// and remember that in order to work, we have been forced to use == nil -> .IsNull cannot be trusted
	forget := func(thing NullValue) (crash error) {
		defer func(in *error) {
			harder := recover()
			if harder != nil {
				*in = fmt.Errorf("bad things happened")
			}
		}(&crash)

		if thing != nil {
			if !thing.IsNull() {
				if _, ok := thing.(NullValue); ok {
					return nil
				}
				return nil
			}
		}

		return fmt.Errorf("it was a nil")
	}

	// this code is the same for everyone
	var buried NullValue
	err := forget(buried)
	if err == nil {
		t.Error(err)
	}
	if !strings.Contains(err.Error(), "was a nil") {
		t.FailNow()
	}
}

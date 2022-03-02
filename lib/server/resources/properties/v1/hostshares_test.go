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

package propertiesv1

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostShare_IsNull(t *testing.T) {

	var hs *HostShare = nil
	if !hs.IsNull() {
		t.Error("HostShare nil pointer is null")
		t.Fail()
	}
	hs = NewHostShare()
	if !hs.IsNull() {
		t.Error("Empty HostShare is null")
		t.Fail()
	}
	hs.ClientsByID = map[string]string{
		"ID": "Client",
	}
	if hs.IsNull() {
		t.Error("HostShare is not null")
		t.Fail()
	}
}

func TestHostShare_Replace(t *testing.T) {

	var hs *HostShare = nil
	hs2 := NewHostShare()
	result := hs.Replace(hs2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("HostShare nil pointer can't be replace")
		t.Fail()
	}

}

func TestHostShare_Clone(t *testing.T) {

	hs := &HostShare{
		ClientsByID: map[string]string{
			"ID": "Client",
		},
		ClientsByName: map[string]string{
			"Name": "Client",
		},
	}

	clonedHs, ok := hs.Clone().(*HostShare)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, hs, clonedHs)
	require.EqualValues(t, hs, clonedHs)
	clonedHs.ClientsByID["ID2"] = "Client2"

	areEqual := reflect.DeepEqual(hs, clonedHs)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, hs, clonedHs)
}

func TestHostShares_IsNull(t *testing.T) {

	var hs *HostShares = nil
	if !hs.IsNull() {
		t.Error("HostShares nil pointer is null")
		t.Fail()
	}
	hs = NewHostShares()
	if !hs.IsNull() {
		t.Error("Empty HostShare is null")
		t.Fail()
	}
	hs = &HostShares{
		ByID: map[string]*HostShare{
			"ID": {
				ClientsByID: map[string]string{
					"ID": "Client",
				},
				ClientsByName: map[string]string{
					"Name": "Client",
				},
			},
		},
		ByName: map[string]string{
			"Name": "ID",
		},
	}
	if hs.IsNull() {
		t.Error("HostShare is not null")
		t.Fail()
	}
}

func TestHostShares_Replace(t *testing.T) {

	var hs *HostShares = nil
	hs2 := NewHostShares()
	result := hs.Replace(hs2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("HostShares nil pointer can't be replace")
		t.Fail()
	}

}

func TestHostShares_Clone(t *testing.T) {

	hs := &HostShares{
		ByID: map[string]*HostShare{
			"ID": {
				ClientsByID: map[string]string{
					"ID": "Client",
				},
				ClientsByName: map[string]string{
					"Name": "Client",
				},
			},
		},
		ByName: map[string]string{
			"Name": "ID",
		},
	}

	clonedHs, ok := hs.Clone().(*HostShares)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, hs, clonedHs)
	require.EqualValues(t, hs, clonedHs)
	clonedHs.ByID["ID2"] = &HostShare{
		ClientsByID: map[string]string{
			"ID2": "Client",
		},
		ClientsByName: map[string]string{
			"Name2": "Client",
		},
	}

	areEqual := reflect.DeepEqual(hs, clonedHs)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, hs, clonedHs)
}

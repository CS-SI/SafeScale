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
	"reflect"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
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
	result, err := hs.Replace(hs2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := hs2.Replace(network)
	if xerr == nil {
		t.Error("HostShare.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *HostShare") {
		t.Errorf("Expect error \"p is not a *HostShare\", has \"%s\"", xerr.Error())
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

	cloned, err := hs.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedHs, ok := cloned.(*HostShare)
	if !ok {
		t.Error("Cloned HostShare not castable to *HostShare", err)
		t.Fail()
	}

	assert.Equal(t, hs, clonedHs)
	require.EqualValues(t, hs, clonedHs)
	clonedHs.ClientsByID["ID2"] = "Client2"

	areEqual := reflect.DeepEqual(hs, clonedHs)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
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
	result, err := hs.Replace(hs2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := hs2.Replace(network)
	if xerr == nil {
		t.Error("HostShares.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *HostShares") {
		t.Errorf("Expect error \"p is not a *HostShares\", has \"%s\"", xerr.Error())
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

	cloned, err := hs.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedHs, ok := cloned.(*HostShares)
	if !ok {
		t.Error("Cloned HostShares not castable to *HostShares", err)
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
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, hs, clonedHs)
}

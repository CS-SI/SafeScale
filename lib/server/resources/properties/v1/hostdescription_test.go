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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
)

func TestHostdescription_IsNull(t *testing.T) {

	var hd *HostDescription = nil
	if !hd.IsNull() {
		t.Error("Nil pointer HostDescription is null")
		t.Fail()
	}
	hd = NewHostDescription()
	if !hd.IsNull() {
		t.Error("No timed HostDescription is null")
		t.Fail()
	}
	hd.Created = time.Now()
	if hd.IsNull() {
		t.Error("ostDescription is not null")
		t.Fail()
	}

}

func TestHostdescription_Clone(t *testing.T) {
	hd := &HostDescription{
		Created: time.Now(),
		Creator: "Hostdescription Creator",
		Updated: time.Now(),
		Purpose: "Hostdescription Purpose",
		Tenant:  "Hostdescription Tenant",
		Domain:  "Hostdescription Domain",
	}

	cloned, err := hd.Clone()
	if err != nil {
		t.Error(err)
	}

	cloneHd, ok := cloned.(*HostDescription)
	if !ok {
		t.Error("Cloned HostDescription shoud be castable to *HostDescription")
		t.FailNow()
	}

	assert.Equal(t, hd, cloneHd)
	require.EqualValues(t, hd, cloneHd)
	cloneHd.Creator = "Hostdescription Creator2"

	areEqual := reflect.DeepEqual(hd, cloneHd)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, hd, cloneHd)
}

func TestHostdescription_Replace(t *testing.T) {

	var hd *HostDescription = nil
	var hd2 = NewHostDescription()
	result, err := hd.Replace(hd2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)
	hd = &HostDescription{
		Created: time.Now(),
		Creator: "Hostdescription Creator",
		Updated: time.Now(),
		Purpose: "Hostdescription Purpose",
		Tenant:  "Hostdescription Tenant",
		Domain:  "Hostdescription Domain",
	}
	hd2 = &HostDescription{
		Created: time.Now(),
		Creator: "Hostdescription Creator2",
		Updated: time.Now(),
		Purpose: "Hostdescription Purpose2",
		Tenant:  "Hostdescription Tenant2",
		Domain:  "Hostdescription Domain2",
	}
	result, _ = hd.Replace(hd2)
	areEqual := reflect.DeepEqual(result, hd2)
	if !areEqual {
		t.Error("Replace does not restitute values")
		t.Fail()
	}

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := hd2.Replace(network)
	if xerr == nil {
		t.Error("HostDescription.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *HostDescription") {
		t.Errorf("HostDescription expect error \"p is not a *HostDescription\", has \"%s\"", xerr.Error())
	}

}

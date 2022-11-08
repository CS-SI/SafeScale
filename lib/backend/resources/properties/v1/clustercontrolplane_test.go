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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
)

func TestClusterControlplane_IsNull(t *testing.T) {

	var cc *ClusterControlplane = nil
	if !cc.IsNull() {
		t.Error("Nil pointer ClusterControlplane is null")
		t.Fail()
	}
	cc = &ClusterControlplane{
		VirtualIP: nil,
	}
	if !cc.IsNull() {
		t.Error("ClusterControlplane nil VirtualIP is null")
		t.Fail()
	}
	cc = &ClusterControlplane{
		VirtualIP: &abstract.VirtualIP{
			ID: "MyVirtualIP ID",
		},
	}
	if cc.IsNull() {
		t.Error("ClusterControlplane is not null")
		t.Fail()
	}
}

func TestClusterControlplane_Replace(t *testing.T) {

	var cc *ClusterControlplane = nil
	cc2 := &ClusterControlplane{
		VirtualIP: &abstract.VirtualIP{
			ID: "MyVirtualIP ID",
		},
	}
	err := cc.Replace(cc2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}

	cc = &ClusterControlplane{
		VirtualIP: &abstract.VirtualIP{
			ID: "MyVirtualIP ID",
		},
	}

	network, _ := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	err = cc.Replace(network)
	if err == nil {
		t.Error("ClusterControlplane.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(err.Error(), "p is not a *ClusterControlplane") {
		t.Errorf("Expect error \"p is not a *ClusterControlplane\", has \"%s\"", err.Error())
	}

}

func TestClusterControlplane_Clone(t *testing.T) {
	vip, _ := abstract.NewVirtualIP()
	hc, _ := abstract.NewHostCore()
	hc.Name = "whatever"
	vip.Hosts = append(vip.Hosts, hc)

	ct := newClusterControlPlane()
	ct.VirtualIP = vip

	cloned, err := ct.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCt, ok := cloned.(*ClusterControlplane)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.VirtualIP.Hosts[0].Name = "Test"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}

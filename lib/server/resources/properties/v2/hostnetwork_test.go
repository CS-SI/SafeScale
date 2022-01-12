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

package propertiesv2

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostNetworking_Clone(t *testing.T) {
	ct := &HostNetworking{
		DefaultSubnetID: "id1",
		SubnetsByID:     map[string]string{"id1": "subnet1"},
		SubnetsByName:   map[string]string{"subnet1": "id1"},
		PublicIPv4:      "195.32.4.1",
		IPv4Addresses:   map[string]string{"id1": "192.168.2.10"},
		IPv6Addresses:   map[string]string{"id1": "2001:db8:3333:4444:5555:6666:7777:8888"},
	}

	clonedCt, ok := ct.Clone().(*HostNetworking)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.SubnetsByID["id2"] = "subnet2"
	clonedCt.SubnetsByName["subnet2"] = "id2"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}

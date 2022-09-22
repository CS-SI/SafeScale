//go:build fixme
// +build fixme

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

package operations

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

func createShareIdentity() *ShareIdentity {
	return &ShareIdentity{
		HostID:    "MyHost",
		HostName:  "MyHost",
		ShareID:   "MyShare",
		ShareName: "MyShare",
	}
}

func TestShareIdentity_GetID(t *testing.T) {
	share := createShareIdentity()
	id, xerr := share.GetID() //FIXME: why useless (x, error) error, never used ?
	require.Nil(t, xerr)
	require.EqualValues(t, id, "MyShare")
}

func TestShareIdentity_GetName(t *testing.T) {
	share := createShareIdentity()
	require.EqualValues(t, share.GetName(), "MyShare")
}

func TestShareIdentity_Serialize(t *testing.T) {
	share1 := createShareIdentity()
	sbytes, xerr := share1.Serialize()
	require.Nil(t, xerr)
	require.EqualValues(t, string(sbytes), "{\"host_id\":\"MyHost\",\"host_name\":\"MyHost\",\"share_id\":\"MyShare\",\"share_name\":\"MyShare\"}")
	share2 := &ShareIdentity{}
	xerr = share2.Deserialize(sbytes)
	require.Nil(t, xerr)

	require.EqualValues(t, share1.HostID, share2.HostID)
	require.EqualValues(t, share1.HostName, share2.HostName)
	require.EqualValues(t, share1.ShareID, share2.ShareID)
	require.EqualValues(t, share1.ShareName, share2.ShareName)

}

func TestShareIdentity_IsNull(t *testing.T) {

	var share *ShareIdentity = nil
	require.True(t, share.IsNull())
	share = &ShareIdentity{HostID: "", HostName: "MyHost", ShareID: "", ShareName: "MyShare"}
	require.True(t, share.IsNull())
	share = &ShareIdentity{HostID: "", HostName: "MyHost", ShareID: "MyShare", ShareName: "MyShare"}
	require.False(t, share.IsNull())
	share = &ShareIdentity{HostID: "MyHost", HostName: "", ShareID: "MyShare", ShareName: "MyShare"}
	require.False(t, share.IsNull())
	share = &ShareIdentity{HostID: "MyHost", HostName: "MyHost", ShareID: "", ShareName: "MyShare"}
	require.False(t, share.IsNull())
	share = &ShareIdentity{HostID: "MyHost", HostName: "MyHost", ShareID: "MyShare", ShareName: ""}
	require.False(t, share.IsNull())

}

func TestShareIdentity_Clone(t *testing.T) {

	share := createShareIdentity()
	clone, xerr := share.Clone()
	require.Nil(t, xerr)
	sharecloned, ok := clone.(*ShareIdentity)
	require.True(t, ok)

	require.EqualValues(t, share.HostID, sharecloned.HostID)
	require.EqualValues(t, share.HostName, sharecloned.HostName)
	require.EqualValues(t, share.ShareID, sharecloned.ShareID)
	require.EqualValues(t, share.ShareName, sharecloned.ShareName)

	share.HostID = "test"
	if sharecloned.HostID == "test" {
		t.Error("Swallow clone")
	}

}

func TestShareIdentity_Replace(t *testing.T) {

	share := &ShareIdentity{}
	_, xerr := share.Replace(nil)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	_, xerr = share.Replace(&abstract.Network{})
	require.Contains(t, xerr.Error(), "p is not a *ShareIdentity")

	result, xerr := share.Replace(createShareIdentity())
	require.Nil(t, xerr)
	replaced, ok := result.(*ShareIdentity)
	require.True(t, ok)

	require.EqualValues(t, replaced.HostID, "MyHost")
	require.EqualValues(t, replaced.HostName, "MyHost")
	require.EqualValues(t, replaced.ShareID, "MyShare")
	require.EqualValues(t, replaced.ShareName, "MyShare")

}

func Test_NewShare(t *testing.T) {

	var svc iaas.Service

	share, err := NewShare(svc)
	require.Nil(t, share)
	require.Contains(t, err.Error(), "cannot be nil")

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		share, err := NewShare(svc)
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(share).String(), "*operations.Share")

	})
	if xerr != nil {
		t.Error(xerr)
	}
	require.Nil(t, xerr)

}

func TestShare_IsNull(t *testing.T) {

	var share *Share = nil
	require.True(t, share.IsNull())

	var ctx = context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		share, err := svc._CreateShare(ctx, createShareIdentity())
		require.Nil(t, err)
		require.False(t, share.IsNull())

	})
	require.Nil(t, xerr)

}

func TestShare_GetID(t *testing.T) {

	var ctx = context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		share, err := svc._CreateShare(ctx, createShareIdentity())
		require.Nil(t, err)

		id, xerr := share.GetID()
		require.Nil(t, xerr)
		require.EqualValues(t, id, "MyShare")

		fmt.Println()

	})
	require.Nil(t, xerr)

}

func TestShare_Browse(t *testing.T) {

	var ctx = context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		share, err := svc._CreateShare(ctx, createShareIdentity())
		require.Nil(t, err)

		id, xerr := share.GetID()
		require.Nil(t, xerr)
		require.EqualValues(t, id, "MyShare")

		xerr = share.Browse(ctx, func(hostName string, shareName string) fail.Error {
			require.EqualValues(t, hostName, "MyHost")
			require.EqualValues(t, shareName, "MyShare")
			return nil
		})

	})
	require.Nil(t, xerr)

}

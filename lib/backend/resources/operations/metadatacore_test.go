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
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/mocks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/gojuno/minimock/v3"
	"github.com/stretchr/testify/require"
)

type SomeClonable struct {
	data.Clonable
	data.Identifiable
	value string
}

func (e *SomeClonable) Clone() (data.Clonable, error) {
	return &SomeClonable{value: e.value}, nil
}
func (e *SomeClonable) Replace(data data.Clonable) (data.Clonable, error) {
	e.value = data.(*SomeClonable).value
	return e, nil
}
func (e *SomeClonable) GetValue() string {
	return e.value
}
func (e *SomeClonable) GetName() string {
	return e.value
}
func (e *SomeClonable) GetID() (string, error) {
	return e.value, nil
}

func Test_NewCore(t *testing.T) {

	_, err := NewCore(nil, "kind", "path", nil)
	require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
	require.Contains(t, err.Error(), "invalid parameter: svc")

	serr := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("version", MinimumMetadataVersion)

		_, err := NewCore(svc, "", "path", nil)
		require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
		require.Contains(t, err.Error(), "cannot be empty string")

		_, err = NewCore(svc, "kind", "", nil)
		require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrInvalidParameter")
		require.Contains(t, err.Error(), "cannot be empty string")

		mc, err := NewCore(svc, "network", "networks", &abstract.Network{})
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(mc).String(), "*operations.MetadataCore")

		mc, err = NewCore(svc, clusterKind, "clusters", &abstract.ClusterIdentity{})
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(mc).String(), "*operations.MetadataCore")

		svc._reset()
		svc._updateOption("metadatakey", "")
		svc._updateOption("metadatakeyErr", fail.NewError("No metadata key"))

		_, err = NewCore(svc, "network", "networks", &abstract.Network{})
		require.Contains(t, err.Error(), "No metadata key")

	})
	require.EqualValues(t, serr, nil)

}

func TestMetadataCore_IsNull(t *testing.T) {

	var m *MetadataCore = nil
	require.EqualValues(t, m.IsNull(), true)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	serr := NewServiceTest(t, func(svc *ServiceTest) {

		mc, err := NewCore(svc, "network", "networks", network)
		require.Nil(t, err)
		require.EqualValues(t, network.IsNull(), false)
		require.EqualValues(t, mc.IsNull(), false)

	})
	require.EqualValues(t, serr, nil)

}

func TestMetadataCore_Service(t *testing.T) {

	defer func() {
		if r := recover(); r != nil {
			t.Log("Panic is expected")
		} else {
			t.Error("It should have panicked", r)
			t.Fail()
		}
	}()

	var amc *MetadataCore = nil
	require.EqualValues(t, amc.Service(), nil)

	serr := NewServiceTest(t, func(svc *ServiceTest) {

		amc, xerr := NewCore(svc, "network", "networks", abstract.NewNetwork())
		require.Nil(t, xerr)
		asvc := amc.Service()
		require.EqualValues(t, svc, asvc)

	})
	require.EqualValues(t, serr, nil)

}

func skip(a string, _ error) string {
	return a
}

func TestMetadataCore_GetID(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Log("Panic is expected")
		} else {
			t.Error("It should have panicked", r)
			t.Fail()
		}
	}()

	var amc *MetadataCore = nil
	ctx := context.Background()

	require.EqualValues(t, skip(amc.GetID()), "")

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	serr := NewServiceTest(t, func(svc *ServiceTest) {

		mc, xerr := NewCore(svc, "network", "networks", network)
		require.Nil(t, xerr)
		require.EqualValues(t, skip(mc.GetID()), "")

		xerr = mc.Carry(ctx, network)
		require.Nil(t, xerr)
		require.EqualValues(t, skip(mc.GetID()), "Network ID")

	})
	require.EqualValues(t, serr, nil)

}

func TestMetadataCore_GetName(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Log("Panic is expected")
		} else {
			t.Error("It should have panicked", r)
			t.Fail()
		}
	}()

	ctx := context.Background()

	var amc *MetadataCore = nil
	require.EqualValues(t, amc.GetName(), "")

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	serr := NewServiceTest(t, func(svc *ServiceTest) {

		mc, xerr := NewCore(svc, "network", "networks", network)
		require.Nil(t, xerr)
		require.EqualValues(t, mc.GetName(), "")

		xerr = mc.Carry(ctx, network)
		require.Nil(t, xerr)
		require.EqualValues(t, mc.GetName(), "Network Name")

	})
	require.EqualValues(t, serr, nil)

}

func TestMetadataCore_GetKind(t *testing.T) {

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	serr := NewServiceTest(t, func(svc *ServiceTest) {

		mc, err := NewCore(svc, "network", "networks", network)
		require.Nil(t, err)
		require.EqualValues(t, mc.GetKind(), "network")

	})
	require.EqualValues(t, serr, nil)

}

func TestMetadataCore_Bait(t *testing.T) {
	mc := minimock.NewController(t)

	sm := mocks.NewServiceMock(mc)
	sm.GetMetadataKeyMock.Expect().Return(nil, nil)
	sm.TimingsMock.Expect().Return(SHORTEN_TIMINGS, nil)
	ctx, wick := context.WithCancel(context.Background())
	defer wick()
	sm.GetMetadataBucketMock.Return(*abstract.NewObjectStorageBucket(), nil)
	sm.WriteObjectMock.Return(abstract.ObjectStorageItem{}, nil)
	var foo bytes.Buffer
	foo.WriteString("{\"id\":\"Network_ID\",\"mask\":\"\",\"name\":\"Network Name\",\"properties\":{},\"tags\":{\"CreationDate\":\"2022-11-08T14:05:44+01:00\",\"ManagedBy\":\"safescale\"}")
	sm.ReadObjectMock.Return(foo, nil)
	sm.InvalidateObjectMock.Return(nil)

	net := abstract.NewNetwork()
	net.ID = "Network_ID"
	net.Name = "Network Name"

	mk, xerr := NewCore(sm, "network", "networks", net)
	require.Nil(t, xerr)
	require.NotNil(t, mk)

	xerr = mk.Reload(ctx)
	require.Nil(t, xerr)

	xerr = mk.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		require.EqualValues(t, reflect.TypeOf(clonable).String(), "*abstract.Network")

		an, ok := clonable.(*abstract.Network)
		require.True(t, ok)
		require.EqualValues(t, skip(an.GetID()), "Network_ID")
		require.EqualValues(t, an.GetName(), "cook kids")
		require.EqualValues(t, an.DNSServers, []string{"1.1.1.1"})

		return nil
	})
	require.Nil(t, xerr)
}

func TestMetadataCore_TrueInspect(t *testing.T) {
	mc := minimock.NewController(t)

	sm := mocks.NewServiceMock(mc)
	sm.GetMetadataKeyMock.Expect().Return(nil, nil)
	sm.TimingsMock.Expect().Return(SHORTEN_TIMINGS, nil)
	ctx, wick := context.WithCancel(context.Background())
	defer wick()
	sm.GetMetadataBucketMock.Return(*abstract.NewObjectStorageBucket(), nil)
	sm.WriteObjectMock.Return(abstract.ObjectStorageItem{}, nil)
	var foo bytes.Buffer
	foo.WriteString("{\"id\":\"Network_ID\",\"mask\":\"\",\"name\":\"Network Name\",\"properties\":{},\"tags\":{\"CreationDate\":\"2022-11-08T14:05:44+01:00\",\"ManagedBy\":\"safescale\"}")
	sm.ReadObjectMock.Return(foo, nil)
	sm.InvalidateObjectMock.Return(nil)

	net := abstract.NewNetwork()
	net.ID = "Network_ID"
	net.Name = "Network Name"

	mk, xerr := NewCore(sm, "network", "networks", net)
	require.Nil(t, xerr)
	require.NotNil(t, mk)

	xerr = mk.Carry(ctx, net)
	require.Nil(t, xerr)

	wg := sync.WaitGroup{}
	wg.Add(50)
	go func() {
		defer wg.Done()
		xerr := mk.Alter(ctx, func(clonable data.Clonable, properties *serialize.JSONProperties) fail.Error {
			fmt.Println("Have the lock")
			an, _ := clonable.(*abstract.Network)
			an.DNSServers = []string{"1.1.1.1"}
			an.Name = "cook kids"
			fmt.Println("Flushing")
			return nil
		})
		if xerr != nil {
			fmt.Println("Disaster x")
		}
	}()
	for i := 0; i < 49; i++ {
		go func() {
			defer wg.Done()
			fmt.Println("Solar Power")
			xerr := mk.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
				an, ok := clonable.(*abstract.Network)
				require.True(t, ok)
				require.EqualValues(t, skip(an.GetID()), "Network_ID")
				return nil
			})
			if xerr != nil {
				fmt.Println("Disaster")
			}
		}()
	}
	wg.Wait()

	xerr = mk.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		require.EqualValues(t, reflect.TypeOf(clonable).String(), "*abstract.Network")

		an, ok := clonable.(*abstract.Network)
		require.True(t, ok)
		require.EqualValues(t, skip(an.GetID()), "Network_ID")
		require.EqualValues(t, an.GetName(), "cook kids")
		require.EqualValues(t, an.DNSServers, []string{"1.1.1.1"})

		return nil
	})
	require.Nil(t, xerr)

	time.Sleep(4 * time.Second)
}

func TestMetadataCore_Inspect(t *testing.T) {

	ctx := context.Background()

	var amc *MetadataCore = nil
	xerr := amc.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return nil
	})
	require.Contains(t, xerr.Error(), "calling method from a nil pointer")

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network Name"

	var callback func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error

	err := NewServiceTest(t, func(svc *ServiceTest) {

		// svc._setInternalData("networks/byID/Network_ID", network)

		mc, xerr := NewCore(svc, "network", "networks", network)
		require.Nil(t, xerr)

		xerr = mc.Carry(ctx, network)
		require.Nil(t, xerr)

		xerr = mc.Inspect(ctx, callback)
		require.Contains(t, xerr.Error(), "cannot be nil")

		xerr = mc.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			require.EqualValues(t, reflect.TypeOf(clonable).String(), "*abstract.Network")

			an, ok := clonable.(*abstract.Network)
			require.True(t, ok)
			require.EqualValues(t, skip(an.GetID()), "Network_ID")
			require.EqualValues(t, an.GetName(), "Network Name")

			return nil
		})
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

func TestMetadataCore_Review(t *testing.T) {

	ctx := context.Background()

	var amc *MetadataCore = nil
	xerr := amc.Review(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return nil
	})
	require.Contains(t, xerr.Error(), "calling method from a nil pointer")

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network Name"

	var callback func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error

	err := NewServiceTest(t, func(svc *ServiceTest) {

		// svc._setInternalData("networks/byID/Network_ID", network)

		mc, xerr := NewCore(svc, "network", "networks", network)
		require.Nil(t, xerr)

		xerr = mc.Carry(ctx, network)
		require.Nil(t, xerr)

		xerr = mc.Review(ctx, callback)
		require.Contains(t, xerr.Error(), "cannot be nil")

		xerr = mc.Review(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			require.EqualValues(t, reflect.TypeOf(clonable).String(), "*abstract.Network")

			an, ok := clonable.(*abstract.Network)

			require.EqualValues(t, ok, true)
			require.EqualValues(t, skip(an.GetID()), "Network_ID")
			require.EqualValues(t, an.GetName(), "Network Name")

			return nil
		})
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

func TestMetadataCore_Alter(t *testing.T) {
	ctx := context.Background()

	var amc *MetadataCore = nil
	xerr := amc.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return nil
	})
	require.Contains(t, xerr.Error(), "calling method from a nil pointer")

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network Name"

	var callback func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error

	err := NewServiceTest(t, func(svc *ServiceTest) {

		// svc._setInternalData("networks/byID/Network_ID", network)
		// svc._setInternalData("networks/byName/Network Name", network)

		mc, xerr := NewCore(svc, "network", "networks", network)
		require.Nil(t, xerr)

		xerr = mc.Carry(ctx, network)
		require.Nil(t, xerr)

		xerr = mc.Alter(ctx, callback)
		require.Contains(t, xerr.Error(), "cannot be nil")

		xerr = mc.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {

			require.EqualValues(t, reflect.TypeOf(clonable).String(), "*abstract.Network")

			n, ok := clonable.(*abstract.Network)
			if !ok {
				t.Error("Clonable object as *abstract.Network expected")
				t.Fail()
			}
			n.Name = "Network Name 2"

			return nil
		})
		require.Nil(t, xerr)

		xerr = mc.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {

			require.EqualValues(t, reflect.TypeOf(clonable).String(), "*abstract.Network")

			n, ok := clonable.(*abstract.Network)
			if !ok {
				t.Error("Clonable object as *abstract.Network expected")
				t.Fail()
			}
			require.EqualValues(t, n.Name, "Network Name 2")

			return nil
		})
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

func TestMetadataCore_Carry(t *testing.T) {

	ctx := context.Background()

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network Name"

	var amc *MetadataCore = nil
	xerr := amc.Carry(ctx, network)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	amc = &MetadataCore{}
	xerr = amc.Carry(ctx, network)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		// svc._setInternalData("networks/byID/Network_ID", network)
		// svc._setInternalData("networks/byName/Network Name", network)

		mc, err := NewCore(svc, "network", "networks", network)
		require.Nil(t, err)
		xerr = mc.Carry(ctx, network)
		require.Nil(t, xerr)

		xerr = mc.Carry(ctx, network)
		require.Contains(t, xerr.Error(), "cannot carry, already carries something")

	})
	require.Nil(t, err)
}

func TestMetadataCore_Read(t *testing.T) {

	ctx := context.Background()

	var amc *MetadataCore = nil
	xerr := amc.Read(ctx, "networks/byID/Network_ID")
	require.Contains(t, xerr.Error(), "calling method from a nil pointer")

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network Name"

	err := NewServiceTest(t, func(svc *ServiceTest) {

		err := svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network Name", network)
		require.Nil(t, err)

		mc, err := NewCore(svc, "network", "networks", network)
		require.Nil(t, err)
		err = mc.Read(ctx, "")
		require.Contains(t, err.Error(), "cannot be empty string")
		err = mc.Read(ctx, "Network_ID")
		require.Nil(t, err)
		err = mc.Read(ctx, "Network_ID2")
		require.Contains(t, err.Error(), "metadata is already carrying a value")
	})
	require.Nil(t, err)

}

func TestMetadataCore_ReadByID(t *testing.T) {

	ctx := context.Background()

	var amc *MetadataCore = nil
	xerr := amc.ReadByID(ctx, "networks/byID/Network_ID")
	require.Contains(t, xerr.Error(), "calling method from a nil pointer")

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network_Name"

	cluster := abstract.NewClusterIdentity()
	cluster.Name = "Cluster_Name"

	err := NewServiceTest(t, func(svc *ServiceTest) {

		err := svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network Name", network)
		require.Nil(t, err)
		err = svc._setInternalData("clusters/Cluster_Name", cluster)
		require.Nil(t, err)

		mc, err := NewCore(svc, "network", "networks", network)
		require.Nil(t, err)
		xerr = mc.ReadByID(ctx, "")
		require.Contains(t, xerr.Error(), "cannot be empty string")
		xerr = mc.ReadByID(ctx, "Network_NotFound")
		require.Contains(t, xerr.Error(), "not found")
		xerr = mc.ReadByID(ctx, "Network_ID")
		require.Nil(t, xerr)
		xerr = mc.ReadByID(ctx, "Network_ID2")
		require.Contains(t, xerr.Error(), "metadata is already carrying a value")

		mc, err = NewCore(svc, "cluster", "clusters", cluster)
		require.Nil(t, err)
		xerr = mc.ReadByID(ctx, "Cluster_NotFound")
		require.Contains(t, xerr.Error(), "not found")
		xerr = mc.ReadByID(ctx, "Cluster_Name")
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

func TestMetadataCore_Reload(t *testing.T) {
	ctx := context.Background()

	var amc *MetadataCore = nil
	xerr := amc.Reload(ctx)
	require.Contains(t, xerr.Error(), "calling method from a nil pointer")

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network_Name"

	cluster := abstract.NewClusterIdentity()
	cluster.Name = "Cluster_Name"

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("timings", nil)
		svc._updateOption("timingsErr", fail.NewError("No timings defined"))
		err := svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network Name", network)
		require.Nil(t, err)

		mc, err := NewCore(svc, "network", "networks", network)
		require.Nil(t, err)
		xerr = mc.Reload(ctx)
		require.Contains(t, xerr.Error(), "No timings defined")

		svc._reset()
		err = svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network Name", network)
		require.Nil(t, err)
		err = svc._setInternalData("clusters/Cluster_Name", cluster)
		require.Nil(t, err)

		mc, err = NewCore(svc, "network", "networks", network)
		require.Nil(t, err)
		xerr = mc.Carry(ctx, network)
		require.Nil(t, xerr)

		xerr = mc.Reload(ctx)
		require.Nil(t, xerr)

		mc, err = NewCore(svc, "cluster", "clusters", cluster)
		require.Nil(t, err)
		xerr = mc.Carry(ctx, cluster)
		require.Nil(t, xerr)

		xerr = mc.Reload(ctx)
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

func TestMetadataCore_BrowseFolder(t *testing.T) {

	ctx := context.Background()

	var amc *MetadataCore = nil
	xerr := amc.BrowseFolder(ctx, func(data []byte) fail.Error {
		return nil
	})
	require.Contains(t, xerr.Error(), "calling method from a nil pointer")
	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network Name"

	var callback func(data []byte) fail.Error

	err := NewServiceTest(t, func(svc *ServiceTest) {

		// svc._setInternalData("networks/byID/Network_ID", network)
		// svc._setInternalData("networks/byName/Network Name", network)

		mc, err := NewCore(svc, "network", "networks", network)
		require.Nil(t, err)
		xerr := mc.BrowseFolder(ctx, callback)
		require.Contains(t, xerr.Error(), "cannot be nil")

		xerr = mc.BrowseFolder(ctx, func(data []byte) fail.Error {
			str := string(data)
			require.Contains(t, str, "\"id\":\"Network_ID\"")
			require.Contains(t, str, "\"name\":\"Network Name\"")
			return nil
		})
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

func TestMetadataCore_Delete(t *testing.T) {

	ctx := context.Background()

	var amc *MetadataCore = nil
	xerr := amc.Delete(ctx)
	require.Contains(t, xerr.Error(), "calling method from a nil pointer")

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network Name"

	err := NewServiceTest(t, func(svc *ServiceTest) {

		err := svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network Name", network)
		require.Nil(t, err)

		mc, err := NewCore(svc, "network", "networks", network)
		require.Nil(t, err)

		err = mc.Carry(ctx, network)
		require.Nil(t, err)

		err = mc.Delete(ctx)
		require.Nil(t, err)

		// Check if deleted
		xerr = mc.ReadByID(ctx, "Network_ID")
		require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrNotFound")

	})
	require.Nil(t, err)

}

func TestMetadataCore_UnsafeSerialize(t *testing.T) {

	ctx := context.Background()

	var amc *MetadataCore = nil
	_, xerr := amc.unsafeSerialize(ctx)

	// require.Contains(t, xerr.Error(), "calling method from a nil pointer"), true)
	require.Contains(t, xerr.Error(), "runtime error: invalid memory address or nil pointer dereference") // FIXME: aw, runtime error -__-

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network Name"

	err := NewServiceTest(t, func(svc *ServiceTest) {

		err := svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network Name", network)
		require.Nil(t, err)

		mc, err := NewCore(svc, "network", "networks", network)
		require.Nil(t, err)

		err = mc.Carry(ctx, network)
		require.Nil(t, err)

		data, xerr := mc.unsafeSerialize(ctx)
		require.Nil(t, xerr)
		str := string(data)

		require.Contains(t, str, "\"id\":\"Network_ID\"")
		require.Contains(t, str, "\"name\":\"Network Name\"")

	})
	require.Nil(t, err)

}

func TestMetadataCore_Deserialize(t *testing.T) {

	ctx := context.Background()

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network Name"

	err := NewServiceTest(t, func(svc *ServiceTest) {

		err := svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network Name", network)
		require.Nil(t, err)

		mc, err := NewCore(svc, "network", "networks", network)
		require.Nil(t, err)

		err = mc.Carry(ctx, network)
		require.Nil(t, err)

		data, xerr := mc.unsafeSerialize(ctx)
		require.Nil(t, xerr)
		str := string(data)
		require.Contains(t, str, "\"id\":\"Network_ID\"")
		require.Contains(t, str, "\"name\":\"Network Name\"")

		var amc *MetadataCore = nil
		xerr = amc.Deserialize(ctx, []byte(str))
		require.Contains(t, xerr.Error(), "calling method from a nil pointer")

		amc, err = NewCore(svc, "network", "networks", network)
		require.Nil(t, err)
		xerr = amc.Deserialize(ctx, []byte(str))
		require.Nil(t, xerr)
		data, xerr = mc.unsafeSerialize(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, str, string(data))

	})
	require.Nil(t, err)

}

type SomeObserver struct {
	observer.Observer
	ID     string
	Name   string
	States map[string]string
}

func (e *SomeObserver) GetID() (string, error) {
	if e == nil {
		return "", nil
	}
	return e.ID, nil
}
func (e *SomeObserver) GetName() string {
	if e == nil {
		return ""
	}
	return e.Name
}
func (e *SomeObserver) GetStates() map[string]string {
	if e == nil {
		return map[string]string{}
	}
	return e.States
}

// is called by Observable to signal an Observer a change occurred
func (e *SomeObserver) SignalChange(id string) {
	e.States[id] = "changed"
}

// is called by Observable to signal an Observer the content will not be used anymore (decreasing the counter of uses)
func (e *SomeObserver) MarkAsFreed(id string) {
	e.States[id] = "markasreed"
}

// used to mark the Observable as deleted (allowing to remove the entry from the Observer internals)
func (e *SomeObserver) MarkAsDeleted(id string) {
	e.States[id] = "markasdeleted"
}

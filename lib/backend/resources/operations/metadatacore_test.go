//go:build testable
// +build testable

package operations

import (
	"bytes"
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/mocks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/gojuno/minimock/v3"
	"github.com/stretchr/testify/require"
)

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
	foo.WriteString("{\"id\":\"Network_ID\",\"mask\":\"\",\"name\":\"Network Name\",\"properties\":{},\"tags\":{\"ManagedBy\":\"safescale\"}}")
	sm.ReadObjectMock.Return(foo, nil)
	sm.InvalidateObjectMock.Return(nil)

	net := abstract.NewNetwork()
	net.ID = "Network_ID"
	net.Name = "Network Name"
	delete(net.Tags, "CreationDate")

	mk, xerr := NewCore(sm, "network", "networks", net)
	require.Nil(t, xerr)
	require.NotNil(t, mk)

	xerr = mk.Carry(ctx, net)
	require.Nil(t, xerr)

	xerr = mk.Reload(ctx)
	require.Nil(t, xerr)

	xerr = mk.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		require.EqualValues(t, reflect.TypeOf(clonable).String(), "*abstract.Network")

		an, ok := clonable.(*abstract.Network)
		require.True(t, ok)
		require.EqualValues(t, skip(an.GetID()), "Network_ID")
		require.EqualValues(t, an.GetName(), "Network Name")

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
	foo.WriteString("{\"id\":\"Network_ID\",\"mask\":\"\",\"name\":\"Network Name\",\"properties\":{},\"tags\":{\"ManagedBy\":\"safescale\"}}")
	sm.ReadObjectMock.Return(foo, nil)
	sm.InvalidateObjectMock.Return(nil)

	net := abstract.NewNetwork()
	net.ID = "Network_ID"
	net.Name = "Network Name"
	delete(net.Tags, "CreationDate")

	mk, xerr := NewCore(sm, "network", "networks", net)
	require.Nil(t, xerr)
	require.NotNil(t, mk)

	xerr = mk.Carry(ctx, net)
	require.Nil(t, xerr)

	xerr = mk.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		_, ok := clonable.(*abstract.Network)
		require.True(t, ok)

		return nil
	})
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
			fmt.Printf("Disaster x: %v\n", xerr)
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
				fmt.Printf("Disaster y: %v\n", xerr)
			}
		}()
	}
	wg.Wait()

	xerr = mk.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		_, ok := clonable.(*abstract.Network)
		require.True(t, ok)

		return nil
	})
	require.Nil(t, xerr)

	time.Sleep(4 * time.Second)
}

func TestMetadataCore_Darkbloom(t *testing.T) {
	ol, err := objectstorage.NewLocation(objectstorage.Config{
		Type:        "s3",
		EnvAuth:     false,
		AuthVersion: 0,
		Endpoint:    "http://192.168.1.100:9000",
		User:        "admin",
		SecretKey:   "password",
		Region:      "stub",
		BucketName:  "bushido",
		Direct:      true,
	})
	if err != nil {
		t.Skip()
	}
	ok, err := ol.CreateBucket(context.Background(), "bushido")
	if err != nil {
		ok, _ = ol.InspectBucket(context.Background(), "bushido")
	}

	sm := &minService{
		loc: ol,
		aob: ok,
	}
	net := abstract.NewNetwork()
	net.ID = "Network_ID"
	net.Name = "Network Name"
	delete(net.Tags, "CreationDate")

	mk, xerr := NewCore(sm, "network", "networks", net)
	require.Nil(t, xerr)
	require.NotNil(t, mk)

	xerr = mk.Carry(context.Background(), net)
	require.Nil(t, xerr)

	debug.SetupError("metadatacore_debug.go:450:p:1")
	defer func() {
		debug.SetupError("")
	}()

	ctx := context.Background()

	xerr = mk.Alter(ctx, func(clonable data.Clonable, properties *serialize.JSONProperties) fail.Error {
		an, _ := clonable.(*abstract.Network)
		an.DNSServers = []string{"1.1.1.1"}
		an.Name = "cook kids"
		return nil
	})
	require.NotNil(t, xerr)

	xerr = mk.Inspect(context.Background(), func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		require.True(t, ok)
		require.EqualValues(t, "Network Name", an.Name)

		return nil
	})
	require.Nil(t, xerr)
}

func TestMetadataCore_CrazyWhatLoveCanDo(t *testing.T) {
	ol, err := objectstorage.NewLocation(objectstorage.Config{
		Type:        "s3",
		EnvAuth:     false,
		AuthVersion: 0,
		Endpoint:    "http://192.168.1.100:9000",
		User:        "admin",
		SecretKey:   "password",
		Region:      "stub",
		BucketName:  "bushido",
		Direct:      true,
	})
	if err != nil {
		t.Skip()
	}
	ok, err := ol.CreateBucket(context.Background(), "bushido")
	if err != nil {
		ok, _ = ol.InspectBucket(context.Background(), "bushido")
	}

	sm := &minService{
		loc: ol,
		aob: ok,
	}
	net := abstract.NewNetwork()
	net.ID = "Network_ID"
	net.Name = "Network Name"
	delete(net.Tags, "CreationDate")

	mk, xerr := NewCore(sm, "network", "networks", net)
	require.Nil(t, xerr)
	require.NotNil(t, mk)

	xerr = mk.Carry(context.Background(), net)
	require.Nil(t, xerr)

	debug.SetupError("metadatacore_debug.go:472:p:1")
	defer func() {
		debug.SetupError("")
	}()

	ctx := context.Background()

	xerr = mk.Alter(ctx, func(clonable data.Clonable, properties *serialize.JSONProperties) fail.Error {
		an, _ := clonable.(*abstract.Network)
		an.DNSServers = []string{"1.1.1.1"}
		an.Name = "cook kids"
		return nil
	})
	require.NotNil(t, xerr)

	xerr = mk.Inspect(context.Background(), func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		require.True(t, ok)
		require.EqualValues(t, "Network Name", an.Name)

		return nil
	})
	require.Nil(t, xerr)
}

func TestMetadataCore_Doctor(t *testing.T) {
	ol, _ := objectstorage.NewLocation(objectstorage.Config{
		Type:        "s3",
		EnvAuth:     false,
		AuthVersion: 0,
		Endpoint:    "http://192.168.1.100:9000",
		User:        "admin",
		SecretKey:   "password",
		Region:      "stub",
		BucketName:  "bushido",
		Direct:      true,
	})
	ok, err := ol.CreateBucket(context.Background(), "bushido")
	if err != nil {
		ok, _ = ol.InspectBucket(context.Background(), "bushido")
	}

	sm := &minService{
		loc: ol,
		aob: ok,
	}
	net := abstract.NewNetwork()
	net.ID = "Network_ID"
	net.Name = "Network Name"
	delete(net.Tags, "CreationDate")

	mk, xerr := NewCore(sm, "network", "networks", net)
	require.Nil(t, xerr)
	require.NotNil(t, mk)

	xerr = mk.Carry(context.Background(), net)
	require.Nil(t, xerr)

	ctx := context.Background()

	xerr = mk.Delete(ctx)
	require.Nil(t, xerr)

	is, xerr := mk.IsValid()
	require.Nil(t, xerr)
	require.EqualValues(t, false, is)

	xerr = mk.Inspect(context.Background(), func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		require.True(t, ok)
		require.EqualValues(t, "Network Name", an.Name)

		return nil
	})
	require.NotNil(t, xerr)
	switch xerr.(type) {
	case *fail.ErrInconsistent:
	default:
		t.Errorf("wrong error type")
	}
}

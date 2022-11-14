//go:build testable
// +build testable

package operations

import (
	"fmt"
	"reflect"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
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

package operations

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/mocks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/gojuno/minimock/v3"
	"github.com/stretchr/testify/require"
)

func TestNewMetadataFolder(t *testing.T) {
	mc := minimock.NewController(t)
	sm := mocks.NewServiceMock(mc)
	sm.GetMetadataKeyMock.Expect().Return(nil, nil)
	sm.TimingsMock.Expect().Return(SHORTEN_TIMINGS, nil)
	sm.GetMetadataBucketMock.Expect(context.Background()).Return(abstract.ObjectStorageBucket{}, nil)
	sm.WriteObjectMock.Return(abstract.ObjectStorageItem{}, nil)
	var byb bytes.Buffer
	byb.Write([]byte("talk"))
	sm.ReadObjectMock.Return(byb, nil)

	mfo, err := NewMetadataFolder(sm, "foo")
	require.Nil(t, err)
	require.NotNil(t, mfo)

	err = mfo.Write(context.Background(), "basic", "whatever", []byte("talk"))
	require.Nil(t, err)
}

func TestMetadataFolder_Write(t *testing.T) {
	mc := minimock.NewController(t)
	sm := mocks.NewServiceMock(mc)
	sm.GetMetadataKeyMock.Expect().Return(nil, nil)
	sm.TimingsMock.Expect().Return(SHORTEN_TIMINGS, nil)
	sm.GetMetadataBucketMock.Expect(context.Background()).Return(abstract.ObjectStorageBucket{}, nil)
	sm.WriteObjectMock.Return(abstract.ObjectStorageItem{}, nil)
	var byb bytes.Buffer
	byb.Write([]byte("talk"))
	sm.ReadObjectMock.Return(byb, nil)

	mfo, err := NewMetadataFolder(sm, "foo")
	require.Nil(t, err)
	require.NotNil(t, mfo)

	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			err = mfo.Write(context.Background(), "basic", "whatever", []byte("talk"))
			require.Nil(t, err)
		}()
	}
	wg.Wait()
}

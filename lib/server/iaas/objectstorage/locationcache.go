package objectstorage

import (
	"bytes"
	"context"
	"expvar"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/dgraph-io/ristretto"
	"github.com/eko/gocache/v2/cache"
	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"
	"github.com/zserge/metric"
)

type locationcache struct {
	inner        Location
	cacheManager *cache.Cache

	locks map[string]*sync.RWMutex
	mutex *sync.Mutex
}

func newLocationcache(inner Location) (*locationcache, error) {
	ristrettoCache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1000,
		MaxCost:     100,
		BufferItems: 1024,
	})
	if err != nil {
		return nil, err
	}
	ristrettoStore := store.NewRistretto(ristrettoCache, nil)

	cacheManager := cache.New(ristrettoStore)

	return &locationcache{inner: inner, cacheManager: cacheManager, locks: make(map[string]*sync.RWMutex), mutex: &sync.Mutex{}}, nil
}

func (l locationcache) Protocol() (string, fail.Error) {
	return l.inner.Protocol()
}

func (l locationcache) Configuration() (Config, fail.Error) {
	return l.inner.Configuration()
}

func (l locationcache) ListBuckets(s string) ([]string, fail.Error) {
	return l.inner.ListBuckets(s)
}

func (l locationcache) FindBucket(s string) (bool, fail.Error) {
	return l.inner.FindBucket(s)
}

func (l locationcache) InspectBucket(s string) (abstract.ObjectStorageBucket, fail.Error) {
	return l.inner.InspectBucket(s)
}

func (l locationcache) CreateBucket(s string) (abstract.ObjectStorageBucket, fail.Error) {
	return l.inner.CreateBucket(s)
}

func (l locationcache) DeleteBucket(s string) fail.Error {
	return l.inner.DeleteBucket(s)
}

func (l locationcache) HasObject(s string, s2 string) (bool, fail.Error) {
	return l.inner.HasObject(s, s2)
}

func (l locationcache) ClearBucket(s string, s2 string, s3 string) fail.Error {
	return l.inner.ClearBucket(s, s2, s3)
}

func (l locationcache) ListObjects(s string, s2 string, s3 string) ([]string, fail.Error) {
	return l.inner.ListObjects(s, s2, s3)
}

func (l locationcache) InvalidateObject(bucketName string, objectName string) fail.Error {
	mu := l.getLock(bucketName, objectName)
	mu.Lock()
	defer mu.Unlock()

	// just cache update
	_ = l.cacheManager.Delete(context.Background(), fmt.Sprintf("%s:%s", bucketName, objectName))
	time.Sleep(10 * time.Millisecond)

	return nil
}

func (l locationcache) InspectObject(s string, s2 string) (abstract.ObjectStorageItem, fail.Error) {
	mu := l.getLock(s, s2)
	mu.RLock()
	defer mu.RUnlock()

	return l.inner.InspectObject(s, s2)
}

func (l locationcache) ItemEtag(bucketName, objectName string) (_ string, ferr fail.Error) {
	mu := l.getLock(bucketName, objectName)
	mu.RLock()
	defer mu.RUnlock()

	return l.inner.ItemEtag(bucketName, objectName)
}

func incrementExpVar(name string) {
	// increase counter
	ts := expvar.Get(name)
	if ts != nil {
		switch casted := ts.(type) {
		case *expvar.Int:
			casted.Add(1)
		case metric.Metric:
			casted.Add(1)
		}
	}
}

func elapsed(what string) func() { // nolint
	start := time.Now()
	logrus.Tracef("starting %s", what)
	return func() {
		logrus.Tracef("%s took %v\n", what, time.Since(start))
	}
}

func (l locationcache) getLock(s string, s2 string) *sync.RWMutex {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	// defer elapsed(fmt.Sprintf("getLock for %s,%s", s, s2))()

	key := fmt.Sprintf("%s:%s", s, s2)
	if mu, ok := l.locks[key]; ok {
		return mu
	}

	l.locks[key] = &sync.RWMutex{}
	mu, _ := l.locks[key] // nolint
	return mu
}

func (l locationcache) ReadObject(s string, s2 string, writer io.Writer, i int64, i2 int64) fail.Error {
	mu := l.getLock(s, s2)
	mu.RLock()
	defer mu.RUnlock()

	bgctx := context.Background()
	ctx, cancel := context.WithCancel(bgctx)
	defer cancel()

	var buffer2 bytes.Buffer
	rewriter := io.MultiWriter(writer, &buffer2)

	ct, err := l.cacheManager.Get(ctx, fmt.Sprintf("%s:%s", s, s2))
	if err == nil {
		buf, _ := ct.([]byte) // nolint
		_, err = rewriter.Write(buf)
		if err != nil {
			return fail.ConvertError(err)
		}

		incrementExpVar("metadata.cache.hits")

		return nil
	}

	incrementExpVar("readobject")
	incrementExpVar("metadata.reads")

	xerr := l.inner.ReadObject(s, s2, rewriter, i, i2)
	if xerr != nil {
		return xerr
	}

	// now we have stuff for our cache in buffer2
	_ = l.cacheManager.Set(ctx, fmt.Sprintf("%s:%s", s, s2), buffer2.Bytes(), nil)
	time.Sleep(10 * time.Millisecond)

	return nil
}

func (l locationcache) WriteMultiPartObject(s string, s2 string, reader io.Reader, i int64, i2 int, metadata abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error) {
	mu := l.getLock(s, s2)
	mu.Lock()
	defer mu.Unlock()

	incrementExpVar("writeobject")
	incrementExpVar("metadata.writes")

	var buf bytes.Buffer
	nr := io.TeeReader(reader, &buf)
	pedasito, err := l.inner.WriteMultiPartObject(s, s2, nr, i, i2, metadata)
	if err != nil {
		return abstract.ObjectStorageItem{}, err
	}

	// now we have stuff for our cache in buffer2
	_ = l.cacheManager.Set(context.Background(), fmt.Sprintf("%s:%s", s, s2), buf.Bytes(), nil)
	time.Sleep(10 * time.Millisecond)

	return pedasito, nil
}

func (l locationcache) WriteObject(s string, s2 string, reader io.Reader, i int64, metadata abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error) {
	mu := l.getLock(s, s2)
	mu.Lock()
	defer mu.Unlock()

	incrementExpVar("writeobject")
	incrementExpVar("metadata.writes")

	var buf bytes.Buffer
	nr := io.TeeReader(reader, &buf)

	pedasito, err := l.inner.WriteObject(s, s2, nr, i, metadata)
	if err != nil {
		return abstract.ObjectStorageItem{}, err
	}

	// now we have stuff for our cache in buffer2
	_ = l.cacheManager.Set(context.Background(), fmt.Sprintf("%s:%s", s, s2), buf.Bytes(), nil)
	time.Sleep(10 * time.Millisecond)

	return pedasito, nil
}

func (l locationcache) DeleteObject(s string, s2 string) fail.Error {
	mu := l.getLock(s, s2)
	mu.Lock()
	defer mu.Unlock()

	err := l.inner.DeleteObject(s, s2)
	if err != nil {
		return err
	}

	// now the cache update
	_ = l.cacheManager.Delete(context.Background(), fmt.Sprintf("%s:%s", s, s2))
	time.Sleep(10 * time.Millisecond)
	return nil
}

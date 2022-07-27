package iaas

import (
	"context"
	"sync"

	"github.com/eko/gocache/v2/cache"
	"github.com/eko/gocache/v2/store"
)

type wrappedCache struct {
	cacheManager *cache.Cache
	mu           sync.RWMutex
}

func NewWrappedCache(cm *cache.Cache) *wrappedCache {
	return &wrappedCache{
		cacheManager: cm,
		mu:           sync.RWMutex{},
	}
}

func (w *wrappedCache) Get(ctx context.Context, key interface{}) (interface{}, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	val, xerr := w.cacheManager.Get(ctx, key)
	/*
		if xerr == nil {
			logrus.Warningf("Returning host %s in %p, %p", key, val, &val)
		}
	*/
	return val, xerr
}

func (w *wrappedCache) Set(ctx context.Context, key, object interface{}, options *store.Options) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := w.cacheManager.Get(ctx, key)
	if err == nil { // already have something in there...
		return nil
	}

	// logrus.Warningf("Registering host %s in %p, %p, type %T", key, object, &object, object)
	return w.cacheManager.Set(ctx, key, object, options)
}

func (w *wrappedCache) Delete(ctx context.Context, key interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.cacheManager.Delete(ctx, key)
}

func (w *wrappedCache) Invalidate(ctx context.Context, options store.InvalidateOptions) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.cacheManager.Invalidate(ctx, options)
}

func (w *wrappedCache) Clear(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.cacheManager.Clear(ctx)
}

func (w *wrappedCache) GetType() string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return w.cacheManager.GetType()
}

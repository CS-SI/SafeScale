package main

import (
	"context"
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgraph-io/ristretto"
	"github.com/eko/gocache/v2/cache"
	_ "github.com/eko/gocache/v2/metrics"
	"github.com/eko/gocache/v2/store"
)

func main() {
	ristrettoCache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1000,
		MaxCost:     100,
		BufferItems: 64,
	})
	if err != nil {
		panic(err)
	}
	ristrettoStore := store.NewRistretto(ristrettoCache, nil)

	cacheManager := cache.New(ristrettoStore)
	ctx := context.TODO() // nolint
	err = cacheManager.Set(ctx, "my-key", "my-value", &store.Options{Cost: 2, Expiration: 15 * time.Minute})
	if err != nil {
		panic(err)
	}

	time.Sleep(10 * time.Millisecond)

	_, err = cacheManager.Get(ctx, "my-key")
	if err != nil {
		panic(err)
	}

	_, err = cacheManager.Get(ctx, "million")
	if err != nil {
		fmt.Println(spew.Sdump(err))
	}

	time.Sleep(1 * time.Second)
	_, err = cacheManager.Get(ctx, "my-key")
	if err != nil {
		panic(err)
	}

	time.Sleep(1 * time.Second)
	_, err = cacheManager.Get(ctx, "my-key")
	if err != nil {
		panic(err)
	}

	time.Sleep(1 * time.Second)
	_, err = cacheManager.Get(ctx, "my-key")
	if err != nil {
		panic(err)
	}

	time.Sleep(1 * time.Second)
	_, err = cacheManager.Get(ctx, "my-key")
	if err != nil {
		panic(err)
	}

	err = cacheManager.Delete(ctx, "my-key")
	if err != nil {
		panic(err)
	}
}

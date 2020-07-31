/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package utils

import (
    "sync"

    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate mockgen -destination=../mocks/mock_cache.go -package=mocks github.com/CS-SI/SafeScale/lib/utils Cache

// Cache is an interface for caching elements
type Cache interface {
    SetBy(string, func() (interface{}, fail.Error)) fail.Error
    Set(string, interface{}) fail.Error
    ForceSetBy(string, func() (interface{}, fail.Error)) fail.Error
    ForceSet(string, interface{}) fail.Error
    Reset(string) Cache
    Get(string) (interface{}, bool)
    GetOrDefault(string, interface{}) interface{}
}

// MapCache implements Cache interface using map
type MapCache struct {
    lock  sync.RWMutex
    cache map[string]interface{}
}

// NewMapCache ...
func NewMapCache() Cache {
    return &MapCache{
        cache: map[string]interface{}{},
    }
}

// SetBy ...
func (c *MapCache) SetBy(key string, by func() (interface{}, fail.Error)) fail.Error {
    c.lock.Lock()
    if _, ok := c.cache[key]; !ok {
        value, err := by()
        if err != nil {
            return err
        }
        c.cache[key] = value
    }
    c.lock.Unlock()
    return nil
}

// ForceSetBy ...
func (c *MapCache) ForceSetBy(key string, by func() (interface{}, fail.Error)) fail.Error {
    c.lock.Lock()
    defer c.lock.Unlock()

    value, xerr := by()
    if xerr != nil {
        return xerr
    }
    c.cache[key] = value
    return nil
}

// Set ...
func (c *MapCache) Set(key string, value interface{}) fail.Error {
    return c.SetBy(key, func() (interface{}, fail.Error) { return value, nil })
}

// ForceSet ...
func (c *MapCache) ForceSet(key string, value interface{}) fail.Error {
    return c.ForceSetBy(key, func() (interface{}, fail.Error) { return value, nil })
}

// Reset ...
func (c *MapCache) Reset(key string) Cache {
    c.lock.Lock()
    defer c.lock.Unlock()

    delete(c.cache, key)
    return c
}

// Get ...
func (c *MapCache) Get(key string) (value interface{}, ok bool) {
    c.lock.RLock()
    defer c.lock.Unlock()

    value, ok = c.cache[key]
    return
}

// GetOrDefault ...
func (c *MapCache) GetOrDefault(key string, def interface{}) (value interface{}) {
    var ok bool
    value, ok = c.Get(key)
    if !ok {
        value = def
    }
    return
}

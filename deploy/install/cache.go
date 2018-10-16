/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package install

import (
	"sync"
)

//go:generate mockgen -destination=../mocks/mock_cache.go -package=mocks github.com/CS-SI/SafeScale/deploy/install Cache

// Cache is an interface for caching elements
type Cache interface {
	SetBy(string, func() (interface{}, error)) error
	Set(string, interface{}) error
	ForceSetBy(string, func() (interface{}, error)) error
	ForceSet(string, interface{}) error
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
func (c *MapCache) SetBy(key string, by func() (interface{}, error)) error {
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
func (c *MapCache) ForceSetBy(key string, by func() (interface{}, error)) error {
	c.lock.Lock()
	value, err := by()
	if err != nil {
		return err
	}
	c.cache[key] = value
	c.lock.Unlock()
	return nil
}

// Set ...
func (c *MapCache) Set(key string, value interface{}) error {
	return c.SetBy(key, func() (interface{}, error) { return value, nil })
}

// ForceSet ...
func (c *MapCache) ForceSet(key string, value interface{}) error {
	return c.ForceSetBy(key, func() (interface{}, error) { return value, nil })
}

// Reset ...
func (c *MapCache) Reset(key string) Cache {
	c.lock.Lock()
	delete(c.cache, key)
	c.lock.Unlock()
	return c
}

// Get ...
func (c *MapCache) Get(key string) (value interface{}, ok bool) {
	c.lock.RLock()
	value, ok = c.cache[key]
	c.lock.RUnlock()
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

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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package consumer

import (
	"context"
	"strings"
	"sync"
	"time"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type KV struct {
	client   *Client
	kv       *consulapi.KV
	lock     *sync.RWMutex
	watchers map[string]*watcher
	prefix   string
	session  *Session
}

func (instance *KV) IsNull() bool {
	return instance == nil || instance.client.IsNull() || instance.kv == nil || instance.lock == nil
}

// Put ...
func (instance *KV) Put(ctx context.Context, key string, value any) fail.Error {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}

	select {
	case <-ctx.Done():
		return fail.AbortedError(nil)
	default:
	}

	instance.lock.RLock()
	fullKey, xerr := instance.absolutePath(key)
	instance.lock.RUnlock()
	if xerr != nil {
		return xerr
	}

	jsoned, err := json.Marshal(value)
	if err != nil {
		return fail.Wrap(err, "failed to marshal value")
	}

	// PUT a new KV pair
	// encoded := make([]byte, base64.StdEncoding.EncodedLen(len(jsoned)))
	// base64.StdEncoding.Encode(encoded, jsoned)
	// p := &consulapi.KVPair{
	// 	Key:   fullKey,
	// 	Value: encoded,
	// }
	p := &consulapi.KVPair{
		Key:     fullKey,
		Value:   jsoned,
		Session: instance.session.id,
	}
	_, err = instance.kv.Put(p, nil)
	if err != nil {
		return fail.Wrap(err, "failed to put entry with key '%s'", key)
	}

	return nil
}

// absolutePath returns the prefixed path of all successive keys
func (instance *KV) absolutePath(keys ...string) (string, fail.Error) {
	if valid.IsNull(instance) {
		return "", fail.InvalidInstanceError()
	}

	if len(keys) == 0 || len(keys[0]) == 0 {
		return instance.prefix, nil
	}

	allKeys := strings.Join(keys, "/")
	if len(instance.prefix) > 0 {
		allKeys = instance.prefix + "/" + allKeys
	}
	return allKeys, nil
}

// Get ...
func (instance *KV) Get(ctx context.Context, key string) (out []byte, _ fail.Error) {
	if valid.IsNull(instance) {
		return out, fail.InvalidInstanceError()
	}

	select {
	case <-ctx.Done():
		return nil, fail.AbortedError(nil)
	default:
	}

	instance.lock.RLock()
	fullKey, xerr := instance.absolutePath(key)
	instance.lock.RUnlock()
	if xerr != nil {
		return nil, xerr
	}

	// Lookup the pair
	pair, _, err := instance.kv.Get(fullKey, nil)
	if err != nil {
		return nil, fail.Wrap(err, "failed to load value of key '%s'", key)
	}

	err = json.Unmarshal(pair.Value, &out)
	if err != nil {
		return nil, fail.Wrap(err, "failed to unmarshal value")
	}

	return out, nil
}

// Delete ...
func (instance *KV) Delete(ctx context.Context, key string) fail.Error {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}

	select {
	case <-ctx.Done():
		return fail.AbortedError(nil)
	default:
	}

	instance.lock.RLock()
	fullKey, xerr := instance.absolutePath(key)
	instance.lock.RUnlock()
	if xerr != nil {
		return xerr
	}

	_, err := instance.kv.Delete(fullKey, nil)
	if err != nil {
		return fail.Wrap(err, "failed to delete key '%s'", key)
	}

	return nil
}

// List ...
func (instance *KV) List(ctx context.Context, key string) (consulapi.KVPairs, fail.Error) {
	if valid.IsNull(instance) {
		return nil, fail.InvalidInstanceError()
	}

	select {
	case <-ctx.Done():
		return nil, fail.AbortedError(nil)
	default:
	}

	instance.lock.RLock()
	fullKey, xerr := instance.absolutePath(key)
	instance.lock.RUnlock()
	if xerr != nil {
		return nil, xerr
	}

	out, _, err := instance.kv.List(fullKey, nil)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	return out, nil
}

// Acquire ...
func (instance *KV) Acquire(key string) (bool, *consulapi.Lock, fail.Error) {
	if valid.IsNull(instance) {
		return false, nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	fullKey, xerr := instance.absolutePath(key)
	instance.lock.RUnlock()
	if xerr != nil {
		return false, nil, xerr
	}

	kp := &consulapi.KVPair{
		Key:     fullKey,
		Session: instance.session.id,
	}
	ok, meta, err := instance.kv.Acquire(kp, nil)
	_ = meta
	if err != nil {
		return false, nil, fail.Wrap(err, "session '%s' failed to acquire lock on key '%s'", instance.session.name, key)
	}

	return ok, nil, nil
}

// Release ...
func (instance *KV) Release(key string) (bool, *consulapi.Lock, fail.Error) {
	if valid.IsNull(instance) {
		return false, nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	fullKey, xerr := instance.absolutePath(key)
	instance.lock.RUnlock()
	if xerr != nil {
		return false, nil, xerr
	}

	kp := &consulapi.KVPair{
		Key:     fullKey,
		Session: instance.session.id,
	}
	ok, meta, err := instance.kv.Release(kp, nil)
	_ = meta
	if err != nil {
		return false, nil, fail.Wrap(err, "session '%s' failed to acquire lock on key '%s'", instance.session.name, key)
	}

	return ok, nil, nil
}

func (instance *KV) Close() fail.Error {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}

	if valid.IsNull(instance.session) {
		return fail.InvalidInstanceContentError("instance.session", "must not be nil")
	}

	return instance.session.Delete()
}

func (instance *KV) watcher(path string) (*watcher, fail.Error) {
	if valid.IsNull(instance) {
		return nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	fullPath, xerr := instance.absolutePath(path)
	if xerr != nil {
		return nil, xerr
	}

	if _, ok := instance.watchers[fullPath]; !ok {
		return nil, fail.NotFoundError()
	}

	return instance.watchers[fullPath], nil
}

func (instance *KV) addWatcher(path string, w *watcher) fail.Error {
	fullPath, xerr := instance.absolutePath(path)
	if xerr != nil {
		return xerr
	}

	if _, ok := instance.watchers[fullPath]; ok {
		return fail.DuplicateError()
	}

	instance.watchers[fullPath] = w
	return nil
}

func (instance *KV) removeWatcher(path string) fail.Error {
	fullPath, xerr := instance.absolutePath(path)
	if xerr != nil {
		return xerr
	}

	if _, ok := instance.watchers[fullPath]; !ok {
		return fail.NotFoundError()
	}

	delete(instance.watchers, fullPath)
	return nil
}

func (instance *KV) cleanWatchers() fail.Error {
	for _, v := range instance.watchers {
		v.Stop()
	}
	instance.watchers = make(map[string]*watcher)
	return nil
}

func (instance *KV) allWatchers() ([]*watcher, fail.Error) {
	out := make([]*watcher, 0, len(instance.watchers))
	for _, v := range instance.watchers {
		out = append(out, v)
	}

	return out, nil
}

func (instance *KV) watcherLoop(path string) {
	logrus.Debugf("watcher on '%s' start...", path)

	w, xerr := instance.watcher(path)
	if xerr != nil {
		logrus.Error(xerr.Error())
		return
	}

	for {
		xerr := w.run(instance.client.config.consulConfig)
		if xerr != nil {
			logrus.Debugf("watcher connect error on path %s: %s", path, xerr)
			time.Sleep(time.Second * 3)
		}

		w, xerr = instance.watcher(path)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				logrus.Debugf("watcher on path %s stopped", path)
				return
			default:
				return
			}
		}

		logrus.Debugf("watcher on path %s reconnect...", path)
	}
}

// Watch ...
func (instance *KV) Watch(ctx context.Context, path string, handler func(*consulapi.KVPair)) fail.Error {
	fullPath, xerr := instance.absolutePath(path)
	if xerr != nil {
		return xerr
	}

	select {
	case <-ctx.Done():
		return fail.AbortedError(nil)
	default:
	}

	watcher, xerr := newWatcher(fullPath)
	if xerr != nil {
		return xerr
	}

	watcher.setHybridHandler(instance.client.config.prefix, handler)
	xerr = instance.addWatcher(path, watcher)
	if xerr != nil {
		return xerr
	}

	go instance.watcherLoop(path)
	return nil
}

// StopWatch ...
func (instance *KV) StopWatch(path ...string) fail.Error {
	if len(path) == 0 {
		return instance.cleanWatchers()
	}

	for _, p := range path {
		w, xerr := instance.watcher(p)
		if xerr != nil {
			return xerr
		}
		if w == nil {
			logrus.Debug("watcher on '%s' already stop", p)
			continue
		}

		instance.removeWatcher(p)
		w.stop()
		for !w.IsStopped() {
		}
	}

	return nil
}

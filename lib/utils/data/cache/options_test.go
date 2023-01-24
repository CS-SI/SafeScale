//go:build ignore
// +build ignore

/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package cache

import (
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

type SomeCacheable struct {
	id   string
	name string
}

func (e *SomeCacheable) Released() error {
	return nil
}
func (e *SomeCacheable) Destroyed() error {
	return nil
}
func (e *SomeCacheable) AddObserver(o observer.Observer) error {
	return nil
}
func (e *SomeCacheable) NotifyObservers() error {
	return nil
}
func (e *SomeCacheable) RemoveObserver(name string) error {
	return nil
}
func (e *SomeCacheable) GetName() string {
	return e.name
}
func (e *SomeCacheable) GetID() string {
	return e.id
}

func Test_MissEventOption(t *testing.T) {

	ikvs := MissEventOption(func() (data Cacheable, xerr fail.Error) { return nil, nil }, 0*time.Second)

	for i := range ikvs {
		switch ikvs[i].Key() {
		case "on_miss":
			fn := ikvs[i].Value().(func() (data Cacheable, xerr fail.Error))
			data, xerr := fn()
			require.Nil(t, data)
			require.Contains(t, xerr.Error(), "invalid timeout for function provided to react on cache miss event: cannot be less or equal to 0")
		default:
			duration := ikvs[i].Value().(time.Duration)
			require.EqualValues(t, duration, 0*time.Second)
		}
	}

	ikvs = MissEventOption(nil, 10*time.Second)

	for i := range ikvs {
		switch ikvs[i].Key() {
		case "on_miss":
			fn := ikvs[i].Value().(func() (data Cacheable, xerr fail.Error))
			data, xerr := fn()
			require.Nil(t, data)
			require.Contains(t, xerr.Error(), "invalid function provided to react on cache miss event: cannot be nil")
		default:
			duration := ikvs[i].Value().(time.Duration)
			require.EqualValues(t, duration, 10*time.Second)
		}
	}

	ikvs = MissEventOption(func() (data Cacheable, xerr fail.Error) { return nil, fail.NewError("any") }, 10*time.Second)

	for i := range ikvs {
		switch ikvs[i].Key() {
		case "on_miss":
			fn := ikvs[i].Value().(func() (data Cacheable, xerr fail.Error))
			data, xerr := fn()
			require.Nil(t, data)
			require.Contains(t, xerr.Error(), "any")
		default:
			duration := ikvs[i].Value().(time.Duration)
			require.EqualValues(t, duration, 10*time.Second)
		}
	}

	cacheable := &SomeCacheable{id: "myid", name: "myname"}
	ikvs = MissEventOption(func() (data Cacheable, xerr fail.Error) { return cacheable, nil }, 10*time.Second)

	for i := range ikvs {
		switch ikvs[i].Key() {
		case "on_miss":
			fn := ikvs[i].Value().(func() (data Cacheable, xerr fail.Error))
			data, xerr := fn()
			require.EqualValues(t, data, cacheable)
			require.Nil(t, xerr)
		default:
			duration := ikvs[i].Value().(time.Duration)
			require.EqualValues(t, duration, 10*time.Second)
		}
	}

}

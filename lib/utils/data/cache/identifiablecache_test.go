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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIdentifiableCache_New(t *testing.T) {

	store, xerr := NewMapStore("store")
	require.NoError(t, xerr)

	_, err := NewIdentifiableCache("", store)
	require.Error(t, err)

}

func TestIdentifiableCache_ReserveEntry(t *testing.T) {

	/*
		var c *cache = nil
		err := c.Reserve("", 1*time.Second)
		if err == nil {
			t.Error("Can't reserve on nil pointer cache")
			t.Fail()
		}
	*/

	store, xerr := NewMapStore("store")
	require.NoError(t, xerr)
	c2, err := NewIdentifiableCache("cache", store)
	if err != nil {
		t.Fail()
	}
	err = c2.ReserveEntry(context.Background(), "", 1*time.Second)
	if err == nil {
		t.Error("Expect empty key error")
		t.Fail()
	}
	err = c2.ReserveEntry(context.Background(), "key", 0*time.Second)
	if err == nil {
		t.Error("Expect timeout=0 error")
		t.Fail()
	}
	err = c2.ReserveEntry(context.Background(), "key", 3*time.Second)
	require.NoError(t, err)

	// Note: in same goroutine, will receive a *fail.ErrDuplicate
	err = c2.ReserveEntry(context.Background(), "key", 1*time.Second)
	require.NotNil(t, err)

}

func TestIdentifiableCache_CommitEntry(t *testing.T) {

	content := newReservation(context.Background(), "store", "content")

	/*
		var c *cache = nil
		_, err := c.Commit("", content)
		if err == nil {
			t.Error("Can't commit on nil pointer cache")
			t.Fail()
		}
	*/

	store, xerr := NewMapStore("store")
	require.NoError(t, xerr)

	c2, err := NewIdentifiableCache("nuka", store)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	err = c2.ReserveEntry(context.Background(), content.GetID(), 100*time.Millisecond)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	time.Sleep(100 * time.Millisecond)

	_, err = c2.CommitEntry(context.Background(), "", content)
	if err == nil {
		t.Error("Expect empty key error")
		t.Fail()
	}

}

func TestIdentifiableCache_FreeEntry(t *testing.T) {

	var rc *SingleCache = nil
	err := rc.FreeEntry(context.Background(), "key")
	if err == nil {
		t.Error("Can't Free on nil pointer cache")
		t.Fail()
	}

	content := newReservation(context.Background(), "store", "content")

	store, xerr := NewMapStore("store")
	require.NoError(t, xerr)

	rc2, err := NewIdentifiableCache("cache", store)
	require.NoError(t, err)

	err = rc2.ReserveEntry(context.Background(), "key", 100*time.Millisecond)
	require.NoError(t, err)

	_, err = rc2.CommitEntry(context.Background(), "key", content)
	require.NoError(t, err)

	err = rc2.FreeEntry(context.Background(), "")
	if err == nil {
		t.Error("Can't Free empty key")
		t.Fail()
	}

}

func TestIdentifiableCache_AddEntry(t *testing.T) {

	content := newReservation(context.Background(), "store", "content")
	var rc *SingleCache = nil
	_, err := rc.AddEntry(context.Background(), content)
	if err == nil {
		t.Error("Can't Add on nil pointer cache")
		t.Fail()
	}

	store, xerr := NewMapStore("store")
	require.NoError(t, xerr)
	rc2, err := NewSingleCache("cache", store)
	require.NoError(t, err)
	_, err = rc2.AddEntry(context.Background(), nil)
	if err == nil {
		t.Error("Can't Add nil content")
		t.Fail()
	}
	_, err = rc2.AddEntry(context.Background(), content)
	require.NoError(t, err)

}

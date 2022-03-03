//go:build alltests
// +build alltests

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
	"testing"
	"time"
)

func TestCache_Entry(t *testing.T) {

	// Empty cache
	/*
		var nilCache *cache = nil
		_, err := nilCache.Entry("What")
		if err == nil {
			t.Error("Should throw a fail.InvalidInstanceError")
			t.FailNow()
		}
	*/

	// Filled cache, empty key
	nukaCola, err := NewCache("nuka")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	_, err = nukaCola.Entry("")
	if err == nil {
		t.Error("Should throw a fail.InvalidParameterCannotBeEmptyStringError")
		t.FailNow()
	}

	// Filled cache, filled key
	nukaCola, err = NewCache("nuka")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	_, err = nukaCola.Entry("key1")
	if err == nil {
		t.Error("Should throw a fail.NotFoundError")
		t.FailNow()
	}

	err = nukaCola.Reserve("key1", 1*time.Second)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	// Cache never created on commited
	_, err = nukaCola.Entry("key1")
	if err == nil {
		t.Error("Should throw a *expired cache* error")
		t.FailNow()
	}

	// Special broken reservation
	err = nukaCola.Reserve("key1", 1*time.Second)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	_, err = nukaCola.Commit("key1", nil)
	if err == nil {
		t.Error("Should throw a fail.InvalidParameterCannotBeNilError(content)")
		t.FailNow()
	}
	r := &reservation{
		key:     "content",
		timeout: 1000,
	}
	_, err = nukaCola.Commit("key1", r)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	_, err = nukaCola.Entry("key1")
	if err == nil {
		t.Error("Should throw a fail.NotFoundError (fail to found entry...broken one)")
		t.FailNow()
	}

}

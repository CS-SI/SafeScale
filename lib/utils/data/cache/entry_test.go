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
	"sync"
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/stretchr/testify/require"
)

func TestEntry_Key(t *testing.T) {

	var nilCache *cache = nil
	_, err := nilCache.Entry("What")
	if err == nil {
		t.Error("Should throw a fail.InvalidInstanceError")
		t.FailNow()
	}

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

	ce := Entry{
		content: data.NewImmutableKeyValue("ID", "Data"),
		lock:    &sync.RWMutex{},
		use:     0,
	}
	result := ce.Key()
	require.EqualValues(t, result, "ID")

}

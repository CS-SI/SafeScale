// +build alltests

/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package serialize

import (
	"sync"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/stretchr/testify/assert"
)

func TestNestedLocksWithWritesDanger(t *testing.T) {
	PropertyTypeRegistry.Register("clusters", "first", &LikeFeatures{})
	PropertyTypeRegistry.Register("clusters", "second", &LikeFeatures{})

	clusters, _ := NewJSONProperties("clusters")
	assert.NotNil(t, clusters)

	task, _ := concurrency.NewUnbreakableTask()

	xerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
		thing := clonable.(*LikeFeatures)
		thing.Installed["Loren"] = "Ipsum"
		return nil
	})
	assert.Nil(t, xerr)

	// Here ve have clusters with "Ipsum", good
	// one at a time ??

	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		oerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
			thing := clonable.(*LikeFeatures)
			thing.Installed["consectur"] = "adipiscing"
			fmt.Println("Got first lock")
			time.Sleep(50 * time.Millisecond)
			return clusters.Inspect(task, "second", func(clonable data.Clonable) fail.Error {
				other := clonable.(*LikeFeatures)
				other.Installed["elit"] = "In"
				fmt.Println("Two locks here")
				return nil
			})
		})
		assert.Nil(t, oerr)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
		oerr := clusters.Alter(task, "second", func(clonable data.Clonable) fail.Error {
			thing := clonable.(*LikeFeatures)
			thing.Installed["consectur"] = "adipiscing"
			fmt.Println("Got second lock")
			time.Sleep(50 * time.Millisecond)
			return clusters.Inspect(task, "first", func(clonable data.Clonable) fail.Error {
				other := clonable.(*LikeFeatures)
				other.Installed["elit"] = "In"
				fmt.Println("Two locks")
				return nil
			})
		})
		assert.Nil(t, oerr)
	}()

	failed := waitTimeout(&wg, 5*time.Second)
	if failed { // It ended with a deadlock
		t.Fail()
	}
}

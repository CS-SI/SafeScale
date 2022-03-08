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
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/observer"
)

//go:generate minimock -o ../mocks/mock_cacheable.go -i github.com/CS-SI/SafeScale/v21/lib/utils/data/cache.Cacheable

// Cacheable is the interface a struct must satisfy to be able to be cached
type Cacheable interface { // FIXME: return error
	observer.Observable // FIXME: also return error

	Released()  // Released tells cache handler the instance is no more used, giving a chance to free this instance from cache
	Destroyed() // Destroyed tells cache handler the instance has been deleted and MUST be removed from cache
}

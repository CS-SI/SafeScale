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

package data

//go:generate mockgen -destination=../mocks/mock_clonable.go -package=mocks github.com/CS-SI/SafeScale/lib/utils/data Cacheable

// Cacheable is the interface a struct must satisfy to be able to be cached
type Cacheable interface {
	Dispose() // Tells cache handler the instance is no more used (giving a chance to free this instance is there are no more use
	Discard() // tells cache handler the instance has been deleted and MUST be removed from cache
}

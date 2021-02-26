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

//go:generate mockgen -destination=../mocks/mock_observer.go -package=mocks github.com/CS-SI/SafeScale/lib/utils/data Observer

// Observer is the interface a struct must satisfy to be observed by outside
type Observer interface {
	Identifiable

	SignalChange(id string)  // is called by Observable to signal an Observer a change occured
	MarkAsDeleted(id string) // used to mark the Observable as deleted (allowing to remove the entry from the Observer internals)
}

// Observable is the interface a struct must satisfy to signal internal change to observers
type Observable interface {
	AddObserver(o Observer) error    // registers an Observer to be kept in touch
	NotifyObservers(id string) error // notify observers a change occured on object identified by id (using Observer.SignalChange)
	RemoveObserver(o Observer) error // deregisters an Observer that will not be notified further
}

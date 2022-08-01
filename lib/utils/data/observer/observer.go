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

package observer

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
)

//go:generate minimock -o mocks/mock_observer.go -i github.com/CS-SI/SafeScale/v22/lib/utils/data/observer.Observer

// Observer is the interface a struct must satisfy to be observed by outside
type Observer interface {
	data.Identifiable // FIXME: Identifiable also has to be refactored to return error, and this change is painful, it impacts everything but also will fix several problems -> it will require its own PR

	// FIXME: It has to return error too
	SignalChange(id string)  // is called by Observable to signal an Observer a change occurred
	MarkAsFreed(id string)   // is called by Observable to signal an Observer the content will not be used any more (decreasing the counter of uses)
	MarkAsDeleted(id string) // used to mark the Observable as deleted (allowing to remove the entry from the Observer internals)
}

//go:generate minimock -o mocks/mock_observable.go -i github.com/CS-SI/SafeScale/v22/lib/utils/data/observer.Observable

// Observable is the interface a struct must satisfy to signal internal change to observers
type Observable interface {
	data.Identifiable // FIXME: Identifiable also has to be refactored to return error, and this change is painful, it impacts everything but also will fix several problems -> it will require its own PR

	AddObserver(o Observer) error // register an Observer to be kept in touch
	// FIXME: This is also wrong, it should be NotifyObservers(Observable) error, to make sure we use the Observable identity
	NotifyObservers() error           // notify observers a change occurred on content (using Observer.SignalChange)
	RemoveObserver(name string) error // deregister an Observer that will not be notified further
}

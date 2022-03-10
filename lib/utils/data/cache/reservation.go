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
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// reservation is a struct to simulate a content of an Entry to "reserve" a key
type reservation struct {
	key         string
	observers   map[string]observer.Observer
	freedCh     chan struct{}
	committedCh chan struct{}
	timeout     time.Duration
	created     time.Time
}

// newReservation creates an instance of reservation
func newReservation(key string /*, duration time.Duration*/) *reservation {
	return &reservation{
		key:         key,
		freedCh:     make(chan struct{}, 1),
		committedCh: make(chan struct{}, 1),
		// timeout:     duration,
		created: time.Now(),
	}
}

// GetID returns the key of the reservation
func (rc reservation) GetID() string {
	return rc.key
}

// GetName returns the key of the reservation
func (rc reservation) GetName() string {
	return rc.key
}

// AddObserver allows to add an observer to a reservation
// Note: is it really needed to do something here ?
func (rc reservation) AddObserver(o observer.Observer) error {
	if _, ok := rc.observers[o.GetID()]; ok {
		return fail.DuplicateError("there is already an Observer identified by '%s'", o.GetID())
	}

	if len(rc.observers) == 0 {
		rc.observers = map[string]observer.Observer{}
	}
	rc.observers[o.GetID()] = o

	return nil
}

// NotifyObservers tells register observers content has changed
func (rc reservation) NotifyObservers() error {
	for _, ob := range rc.observers {
		ob.SignalChange(rc.key)
	}
	return nil
}

// RemoveObserver unregister an Observer identified by its name
func (rc reservation) RemoveObserver(name string) error {
	if _, ok := rc.observers[name]; !ok {
		return fmt.Errorf("not there")
	}
	delete(rc.observers, name)
	return nil
}

// Released is used to inform observers the reservation was released (decreasing the use counter)
func (rc reservation) Released() error {
	for _, ob := range rc.observers {
		ob.MarkAsFreed(rc.key)
	}
	return nil
}

// Destroyed is used to inform observers the reservation was destroyed
func (rc reservation) Destroyed() error {
	for _, ob := range rc.observers {
		ob.MarkAsDeleted(rc.key)
	}
	return nil
}

// freed returns a read-only channel to be notified when the reservation has been freed
func (rc reservation) freed() <-chan struct{} {
	return rc.freedCh
}

// committed returns a read-only channel to be notified when the reservation has been committed
func (rc reservation) committed() <-chan struct{} {
	return rc.committedCh
}

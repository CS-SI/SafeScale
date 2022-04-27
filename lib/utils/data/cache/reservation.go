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
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// reservation is a struct to simulate a content of an Entry to "reserve" a key
type reservation struct {
	storeName   string
	key         string
	requestor   string // contains an identification of what requested the reservation
	observers   map[string]observer.Observer
	freedCh     chan struct{}
	committedCh chan struct{}
	timeout     time.Duration
	created     time.Time
}

// newReservation creates an instance of reservation
func newReservation(ctx context.Context, store, key string) *reservation {
	var requestor string
	task, xerr := concurrency.TaskFromContext(ctx)
	if xerr == nil {
		requestor, _ = task.ID() // nolint
	}

	return &reservation{
		storeName:   store,
		key:         key,
		requestor:   requestor,
		freedCh:     make(chan struct{}, 1),
		committedCh: make(chan struct{}, 1),
		created:     time.Now(),
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

// IsMine tells if the reservation is owned by the current task (taken from context)
// requestor being the ID of the task that has reserved, returns:
//    - false: if requestor is empty string and 'ctx' does contain Task instance
//    - false: if requestor is not empty string and 'ctx' does not contain Task instance or is context.Background()
//    - false: if requestor is not empty string and 'ctx' does contain Task instance and Task ID is not equal to requestor
//    - true:  if requestor is empty string and 'ctx' does not contain Task instance or is equal to context.Background()
//    - true:  if requestor is not empty string and 'ctx' does contain Task instance and Task ID is equal to requestor
func (rc reservation) IsMine(ctx context.Context) bool {
	if valid.IsNil(ctx) || ctx == context.Background() {
		val := rc.requestor == ""
		return val
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	if xerr != nil {
		return rc.requestor == ""
	}

	currentTaskID, xerr := task.ID()
	if xerr != nil {
		return rc.requestor == ""
	}

	return rc.requestor == currentTaskID
}

// AddObserver allows to add an observer to a reservation
// Note: is it really needed to do something here ?
func (rc *reservation) AddObserver(o observer.Observer) error {
	if valid.IsNil(rc) {
		return fail.InvalidInstanceError()
	}

	if len(rc.observers) == 0 {
		rc.observers = map[string]observer.Observer{}
	}
	if _, ok := rc.observers[o.GetID()]; ok {
		return fail.DuplicateError("there is already an Observer identified by '%s'", o.GetID())
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
func (rc *reservation) RemoveObserver(name string) error {
	if valid.IsNil(rc) {
		return fail.InvalidInstanceError()
	}

	if _, ok := rc.observers[name]; !ok {
		return fail.NotFoundError()
	}

	delete(rc.observers, name)
	return nil
}

// Released is used to inform observers the reservation was released (decreasing the use counter)
func (rc *reservation) Released() error {
	if valid.IsNil(rc) {
		return fail.InvalidInstanceError()
	}

	for _, ob := range rc.observers {
		ob.MarkAsFreed(rc.key)
	}
	return nil
}

// Destroyed is used to inform observers the reservation was destroyed
func (rc *reservation) Destroyed() error {
	if valid.IsNil(rc) {
		return fail.InvalidInstanceError()
	}

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

// waitReleased waits until the reservation is released
// Returns:
//  - nil: the reservation is released and can be used again
//  - *fail.ErrTimeout: the reservation has timed out and can be used again
//  - *fail.ErrDuplicate: the reservation is released but a cache entry exist, so can not be reused
func (rc reservation) waitReleased() fail.Error {
	// If key is reserved, we may have to wait reservation committed or freed to determine if
	waitFor := rc.timeout - time.Since(rc.created)

	if waitFor < 0 {
		waitFor = 0
	}
	select {
	case <-rc.freed():
		logrus.Tracef("reservation for key '%s' is freed", rc.key)
		return nil

	case <-rc.committed():
		return fail.DuplicateError("reservation for entry with key '%s' in %s store cannot be reused because a corresponding entry now exists", rc.key, rc.storeName)

	case <-time.After(waitFor):
		xerr := fail.TimeoutError(nil, rc.timeout, "reservation for entry with key '%s' in %s store has expired (requestor=%s)", rc.key, rc.storeName, rc.requestor)
		logrus.Trace(xerr.Error())
		return xerr
	}
}

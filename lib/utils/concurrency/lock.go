/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package concurrency

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"sync"
)

//go:generate mockgen -destination=../mocks/mock_taskedlock.go -package=mocks github.com/CS-SI/SafeScale/lib/utils/concurrency TaskedLock

// TaskedLock ...
type TaskedLock interface {
	RLock(Task) error
	RUnlock(Task) error
	Lock(Task) error
	Unlock(Task) error
}

// taskedLock ...
type taskedLock struct {
	lock       *sync.Mutex
	rwmutex    *sync.RWMutex
	readLocks  map[string]uint64
	writeLocks map[string]uint64
}

// NewTaskedLock ...
func NewTaskedLock() TaskedLock {
	return &taskedLock{
		lock:       &sync.Mutex{},
		rwmutex:    &sync.RWMutex{},
		readLocks:  map[string]uint64{},
		writeLocks: map[string]uint64{},
	}
}

// RLock locks for read in the context if:
// 1. registers the lock for read only if a lock for write is already registered in the context
// 2. registers the lock for read AND effectively lock for read otherwise
func (tm *taskedLock) RLock(task Task) error {
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil!")
	}

	tracer := NewTracer(task, "", Trace.Locks)
	defer tracer.GoingIn().OnExitTrace()()

	tid, err := task.GetID()
	if err != nil {
		return err
	}

	// logrus.Warnf("Calling rlock from %d, with tid %s", goid(), tid)
	tm.lock.Lock()
	access := false
	defer func() {
		tm.lock.Unlock()
		if access {
			tm.rwmutex.RLock()
		}
	}()

	if _, ok := tm.readLocks[tid]; ok {
		tm.readLocks[tid]++
		return nil
	}
	tm.readLocks[tid] = 1
	if _, ok := tm.writeLocks[tid]; !ok {
		tracer.Trace("really RLocking...")
		access = true
		return nil
	}
	tracer.Trace("using running write lock...")
	return nil
}

// RUnlock unregisters the lock for read for the context and unlock for read
// only if no lock for write is registered for the context
func (tm *taskedLock) RUnlock(task Task) error {
	tracer := NewTracer(task, "", Trace.Locks).GoingIn()
	defer tracer.OnExitTrace()()

	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil!")
	}

	tid, err := task.GetID()
	if err != nil {
		return err
	}

	// logrus.Warnf("Calling runlock from %d, with tid %s", goid(), tid)
	tm.lock.Lock()
	access := false
	defer func() {
		tm.lock.Unlock()
		if access {
			tm.rwmutex.RUnlock()
		}
	}()

	if _, ok := tm.readLocks[tid]; !ok {
		tracer.Trace("Can't RUnlock, not RLocked")
		return fmt.Errorf("Can't RUnlock task %s: not RLocked", tid)
	}
	tm.readLocks[tid]--
	if tm.readLocks[tid] == 0 {
		delete(tm.readLocks, tid)
		// If not locked for write, actively unlock for read the RWMutex
		if _, ok := tm.writeLocks[tid]; ok {
			tracer.Trace("in running write lock, doing nothing")
		} else {
			tracer.Trace("really RUnlocking...")
			access = true
		}
	}

	return nil
}

// Lock acquires a write lock.
func (tm *taskedLock) Lock(task Task) error {
	tracer := NewTracer(task, "", Trace.Locks).GoingIn()
	defer tracer.OnExitTrace()()

	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil!")
	}

	tid, err := task.GetID()
	if err != nil {
		return err
	}

	// logrus.Warnf("Calling lock from %d, with tid %s", goid(), tid)
	tm.lock.Lock()
	access := false
	defer func() {
		tm.lock.Unlock()
		if access {
			tm.rwmutex.Lock()
		}
	}()

	// If already locked for write, increments counter for the task
	if _, ok := tm.writeLocks[tid]; ok {
		tm.writeLocks[tid]++
		return nil
	}
	// If already lock for read, returns an error
	if _, ok := tm.readLocks[tid]; ok {
		tracer.Trace("Can't Lock, already RLocked")
		taskID, _ := task.GetID()
		return fmt.Errorf("cannot Lock task '%s': already RLocked", taskID)
	}
	// registers lock for read for the task and actively lock the RWMutex
	tm.writeLocks[tid] = 1
	access = true
	return nil
}

// Unlock releases a write lock
func (tm *taskedLock) Unlock(task Task) error {
	tracer := NewTracer(task, "", Trace.Locks).GoingIn()
	defer tracer.OnExitTrace()()

	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil!")
	}

	tid, err := task.GetID()
	if err != nil {
		return err
	}

	// logrus.Warnf("Calling unlock from %d, with tid %s", goid(), tid)
	tm.lock.Lock()
	access := false
	defer func() {
		tm.lock.Unlock()
		if access {
			tm.rwmutex.Unlock()
		}
	}()

	// a TaskedLock can be Locked then RLocked without problem,
	// but RUnlocks must have been done before Unlock.
	if _, ok := tm.readLocks[tid]; ok {
		tracer.Trace(fmt.Sprintf("Can't Unlock, %d remaining RLock inside", tm.readLocks[tid]))
		return fmt.Errorf("Can't Unlock task '%s': %d remaining RLock inside", tid, tm.readLocks[tid])
	}
	if _, ok := tm.writeLocks[tid]; !ok {
		tracer.Trace("Can't Unlock, not Locked")
		return fmt.Errorf("Can't Unlock task '%s': not Locked", tid)
	}
	tm.writeLocks[tid]--
	if tm.writeLocks[tid] == 0 {
		delete(tm.writeLocks, tid)
		access = true
	}
	return nil
}

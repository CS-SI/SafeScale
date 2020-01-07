/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"sync"
)

//go:generate mockgen -destination=../mocks/mock_taskedlock.go -package=mocks github.com/CS-SI/SafeScale/lib/utils/concurrency TaskedLock

// TaskedLock ...
type TaskedLock interface {
	RLock(Task)
	RUnlock(Task)
	Lock(Task)
	Unlock(Task)
	IsRLocked(Task) bool
	IsLocked(Task) bool
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
func (tm *taskedLock) RLock(task Task) {
	if task == nil {
		return
	}

	tracer := NewTracer(task, "", Trace.Locks)
	defer tracer.GoingIn().OnExitTrace()()

	tid, _ := task.GetID() // FIXME Fix locks later

	tm.lock.Lock()

	if _, ok := tm.readLocks[tid]; ok {
		tm.readLocks[tid]++
		tm.lock.Unlock()
		return
	}
	tm.readLocks[tid] = 1
	if _, ok := tm.writeLocks[tid]; !ok {
		tracer.Trace("really RLocking...")
		tm.lock.Unlock()
		tm.rwmutex.RLock()
		return
	}
	tracer.Trace("using running write lock...")
	tm.lock.Unlock()
}

// RUnlock unregisters the lock for read for the context and unlock for read
// only if no lock for write is registered for the context
func (tm *taskedLock) RUnlock(task Task) {
	tracer := NewTracer(task, "", Trace.Locks).GoingIn()
	defer tracer.OnExitTrace()()

	tid, _ := task.GetID() // FIXME Fix locks later

	tm.lock.Lock()
	defer tm.lock.Unlock()

	if _, ok := tm.readLocks[tid]; !ok {
		tracer.Trace("Can't RUnlock, not RLocked")
		panic(fmt.Sprintf("Can't RUnlock task %s: not RLocked", tid))
	}
	tm.readLocks[tid]--
	if tm.readLocks[tid] == 0 {
		delete(tm.readLocks, tid)
		// If not locked for write, actively unlock for read the RWMutex
		if _, ok := tm.writeLocks[tid]; ok {
			tracer.Trace("in running write lock, doing nothing")
		} else {
			tracer.Trace("really RUnlocking...")
			tm.rwmutex.RUnlock()
		}
	}
}

// Lock acquires a write lock.
func (tm *taskedLock) Lock(task Task) {
	tracer := NewTracer(task, "", Trace.Locks).GoingIn()
	defer tracer.OnExitTrace()()

	tid, _ := task.GetID() // FIXME Fix locks later

	tm.lock.Lock()

	// If already locked for write, increments counter for the task
	if _, ok := tm.writeLocks[tid]; ok {
		tm.writeLocks[tid]++
		tm.lock.Unlock()
		return
	}
	// If already lock for read, panic
	if _, ok := tm.readLocks[tid]; ok {
		tracer.Trace("Can't Lock, already RLocked")
		taskID, _ := task.GetID()
		panic(fmt.Sprintf("cannot Lock task '%s': already RLocked", taskID))
	}
	// registers lock for read for the task and actively lock the RWMutex
	tm.writeLocks[tid] = 1
	tm.lock.Unlock()
	tm.rwmutex.Lock()
}

// Unlock releases a write lock
func (tm *taskedLock) Unlock(task Task) {
	tracer := NewTracer(task, "", Trace.Locks).GoingIn()
	defer tracer.OnExitTrace()()

	tid, _ := task.GetID() // FIXME Fix locks later

	tm.lock.Lock()
	defer tm.lock.Unlock()

	// a TaskedLock can be Locked then RLocked without problem,
	// but RUnlocks must have been done before Unlock.
	if _, ok := tm.readLocks[tid]; ok {
		tracer.Trace(fmt.Sprintf("Can't Unlock, %d remaining RLock inside", tm.readLocks[tid]))
		panic(fmt.Sprintf("Can't Unlock task '%s': %d remaining RLock inside", tid, tm.readLocks[tid]))
	}
	if _, ok := tm.writeLocks[tid]; !ok {
		tracer.Trace("Can't Unlock, not Locked")
		panic(fmt.Sprintf("Can't Unlock task '%s': not Locked", tid))
	}
	tm.writeLocks[tid]--
	if tm.writeLocks[tid] == 0 {
		delete(tm.writeLocks, tid)
		tm.rwmutex.Unlock()
	}
}

// IsRLocked tells if the task is owning a read lock
func (tm *taskedLock) IsRLocked(task Task) bool {
	taskid, _ := task.GetID() // FIXME Fix locks later
	_, ok := tm.readLocks[taskid]
	return ok
}

// IsLocked tells if the task is owning a write lock
func (tm *taskedLock) IsLocked(task Task) bool {
	taskid, _ := task.GetID() // FIXME Fix locks later
	_, ok := tm.writeLocks[taskid]
	return ok
}

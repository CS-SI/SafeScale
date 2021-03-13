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

package concurrency

import (
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate minimock -o ../mocks/mock_taskedlock.go -i github.com/CS-SI/SafeScale/lib/utils/concurrency.TaskedLock

// TaskedLockHelpers ...
type TaskedLockHelpers interface {
	SafeLock(Task)
	SafeUnlock(Task)
	SafeRLock(Task)
	SafeRUnlock(Task)
}

// TaskedLock ...
type TaskedLock interface {
	RLock(Task) fail.Error
	RUnlock(Task) fail.Error
	Lock(Task) fail.Error
	Unlock(Task) fail.Error

	IsRLocked(Task) (bool, fail.Error)
	IsLocked(Task) (bool, fail.Error)

	GetReadLockCount(task Task) (uint64, fail.Error)
	GetWriteLockCount(task Task) (uint64, fail.Error)

	TaskedLockHelpers
}

// taskedLock ...
type taskedLock struct {
	mu         *sync.Mutex
	rwmutex    *sync.RWMutex
	readLocks  map[string]uint64
	writeLocks map[string]uint64
}

// NewTaskedLock ...
func NewTaskedLock() TaskedLock {
	return &taskedLock{
		mu:         &sync.Mutex{},
		rwmutex:    &sync.RWMutex{},
		readLocks:  map[string]uint64{},
		writeLocks: map[string]uint64{},
	}
}

// RLock locks for read in the context if:
// 1. registers the lock for read only if a lock for write is already registered in the context
// 2. registers the lock for read AND effectively lock for read otherwise
func (tm *taskedLock) RLock(task Task) fail.Error {
	if tm == nil {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	traceR := newTracer(task, tracing.ShouldTrace("concurrency.lock")).entering()
	defer traceR.exiting()

	tid, err := task.GetID()
	if err != nil {
		return err
	}

	// logrus.Warnf("Calling rlock from %d, with tid %s", goid(), tid)
	tm.mu.Lock()
	acquired := false
	defer func() {
		tm.mu.Unlock()
		if acquired {
			tm.rwmutex.RLock()
		}
	}()

	if _, ok := tm.readLocks[tid]; ok {
		tm.readLocks[tid]++
		return nil
	}
	tm.readLocks[tid] = 1
	if _, ok := tm.writeLocks[tid]; !ok {
		traceR.trace("really RLocking...")
		acquired = true
		return nil
	}
	traceR.trace("using running write lock...")
	return nil
}

// SafeRLock ...
func (tm *taskedLock) SafeRLock(task Task) {
	err := tm.RLock(task)
	for {
		if err != nil {
			if _, ok := err.(*fail.ErrInvalidInstance); ok {
				logrus.Fatalf(fail.Wrap(err, callstack.DecorateWith("", "cannot use SafeRLock() when obviously it's not safe", "", 0)).Error())
			}
			if _, ok := err.(*fail.ErrInvalidParameter); ok {
				logrus.Fatalf(fail.Wrap(err, callstack.DecorateWith("", "cannot use SafeRLock() when obviously it's not safe", "", 0)).Error())
			}
			err = tm.RLock(task)
		} else {
			break
		}
	}
}

// RUnlock unregisters the mu for read for the context and unlock for read
// only if no mu for write is registered for the context
func (tm *taskedLock) RUnlock(task Task) (xerr fail.Error) {
	traceR := newTracer(task, tracing.ShouldTrace("concurrency.lock")).entering()
	defer traceR.exiting()
	// defer fail.OnExitLogError(&err)

	if tm == nil {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	tid, err := task.GetID()
	if err != nil {
		return err
	}

	// logrus.Warnf("Calling runlock from %d, with tid %s", goid(), tid)
	tm.mu.Lock()
	released := false
	defer func() {
		tm.mu.Unlock()
		if released {
			tm.rwmutex.RUnlock()
		}
	}()

	if _, ok := tm.readLocks[tid]; !ok {
		return fail.ForbiddenError("cannot RUnlock task %s: not RLocked", tid)
	}
	tm.readLocks[tid]--
	if tm.readLocks[tid] == 0 {
		delete(tm.readLocks, tid)
		// If not locked for write, actively unlock for read the RWMutex
		if _, ok := tm.writeLocks[tid]; ok {
			traceR.trace("in running write mu, doing nothing")
		} else {
			traceR.trace("really RUnlocking...")
			released = true
		}
	}

	return nil
}

// SafeRUnlock ...
func (tm *taskedLock) SafeRUnlock(task Task) {
	err := tm.RUnlock(task)
	for {
		if err != nil {
			if _, ok := err.(*fail.ErrInvalidInstance); ok {
				logrus.Fatalf(fail.Wrap(err, callstack.DecorateWith("", "cannot use SafeRUnlock() when obviously it's not safe", "", 0)).Error())
			}
			if _, ok := err.(*fail.ErrInvalidParameter); ok {
				logrus.Fatalf(fail.Wrap(err, callstack.DecorateWith("", "cannot use SafeRUnlock() when obviously it's not safe", "", 0)).Error())
			}
			err = tm.RUnlock(task)
		} else {
			break
		}
	}
}

// Lock acquires a write mu.
func (tm *taskedLock) Lock(task Task) fail.Error {
	traceR := newTracer(task, tracing.ShouldTrace("concurrency.lock")).entering()
	defer traceR.exiting()

	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	tid, err := task.GetID()
	if err != nil {
		return err
	}

	// logrus.Warnf("Calling mu from %d, with tid %s", goid(), tid)
	tm.mu.Lock()
	acquired := false
	defer func() {
		tm.mu.Unlock()
		if acquired {
			tm.rwmutex.Lock()
		}
	}()

	// If already locked for write, increments counter for the task
	if _, ok := tm.writeLocks[tid]; ok {
		tm.writeLocks[tid]++
		return nil
	}
	// If already locked for read, returns an error
	if _, ok := tm.readLocks[tid]; ok {
		traceR.trace("Cannot Lock, already RLocked")
		taskID, _ := task.GetID()
		return fail.ForbiddenError(callstack.DecorateWith("cannot Lock task ", taskID, "already RLocked", 0))
	}
	// registers mu for read for the task and actively mu the RWMutex
	tm.writeLocks[tid] = 1
	acquired = true
	return nil
}

// SafeLock ...
func (tm *taskedLock) SafeLock(task Task) {
	err := tm.Lock(task)
	for {
		if err != nil {
			if _, ok := err.(*fail.ErrInvalidInstance); ok {
				logrus.Fatalf(fail.Wrap(err, callstack.DecorateWith("", "cannot use SafeLock() when obviously it's not safe", "", 0)).Error())
			}
			if _, ok := err.(*fail.ErrInvalidParameter); ok {
				logrus.Fatalf(fail.Wrap(err, callstack.DecorateWith("", "cannot use SafeLock() when obviously it's not safe", "", 0)).Error())
			}
			err = tm.Lock(task)
		} else {
			break
		}
	}
}

// Unlock releases a write mu
func (tm *taskedLock) Unlock(task Task) fail.Error {
	traceR := newTracer(task, tracing.ShouldTrace("concurrency.lock")).entering()
	defer traceR.exiting()

	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	tid, err := task.GetID()
	if err != nil {
		return err
	}

	// logrus.Warnf("Calling unlock from %d, with tid %s", goid(), tid)
	tm.mu.Lock()
	released := false
	defer func() {
		tm.mu.Unlock()
		if released {
			tm.rwmutex.Unlock()
		}
	}()

	// a TaskedLock can be Locked then RLocked without problem,
	// but RUnlocks must have been done before Unlock.
	if _, ok := tm.readLocks[tid]; ok {
		return fail.ForbiddenError("cannot Unlock task '%s': %d remaining RLock inside", tid, tm.readLocks[tid])
	}
	if _, ok := tm.writeLocks[tid]; !ok {
		return fail.ForbiddenError("cannot Unlock task '%s': not Locked", tid)
	}
	tm.writeLocks[tid]--
	if tm.writeLocks[tid] == 0 {
		delete(tm.writeLocks, tid)
		released = true
	}
	return nil
}

// SafeUnlock unlocks a previously lock without possible failure, but will log if something is wrong
func (tm *taskedLock) SafeUnlock(task Task) {
	err := tm.Unlock(task)
	for {
		if err != nil {
			if _, ok := err.(*fail.ErrInvalidInstance); ok {
				logrus.Fatalf(fail.Wrap(err, callstack.DecorateWith("", "cannot use SafeUnlock() when obviously it's not safe", "", 0)).Error())
			}
			if _, ok := err.(*fail.ErrInvalidParameter); ok {
				logrus.Fatalf(fail.Wrap(err, callstack.DecorateWith("", "cannot use SafeUnlock() when obviously it's not safe", "", 0)).Error())
			}
			err = tm.Unlock(task)
		} else {
			break
		}
	}
}

// IsRLocked tells if the task is owning a read lock
func (tm *taskedLock) IsRLocked(task Task) (bool, fail.Error) {
	if tm == nil {
		return false, fail.InvalidInstanceError()
	}
	if task == nil {
		return false, fail.InvalidParameterCannotBeNilError("task")
	}

	tid, err := task.GetID()
	if err != nil {
		return false, err
	}
	tm.rwmutex.RLock()
	defer tm.rwmutex.RUnlock()
	_, ok := tm.readLocks[tid]
	return ok, nil
}

// IsLocked tells if the task is owning a write lock
func (tm *taskedLock) IsLocked(task Task) (bool, fail.Error) {
	if tm == nil {
		return false, fail.InvalidInstanceError()
	}
	if task == nil {
		return false, fail.InvalidParameterCannotBeNilError("task")
	}

	tid, err := task.GetID()
	if err != nil {
		return false, err
	}

	tm.rwmutex.RLock()
	defer tm.rwmutex.RUnlock()
	_, ok := tm.writeLocks[tid]
	return ok, nil
}

// GetReadLockCount ...
func (tm *taskedLock) GetReadLockCount(task Task) (uint64, fail.Error) {
	if tm == nil {
		return 0, fail.InvalidInstanceError()
	}
	if task == nil {
		return 0, fail.InvalidParameterCannotBeNilError("task")
	}

	tid, xerr := task.GetID()
	if xerr != nil {
		return 0, xerr
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if c, ok := tm.readLocks[tid]; ok {
		return c, nil
	}
	return 0, nil
}

// GetWriteLockCount ...
func (tm *taskedLock) GetWriteLockCount(task Task) (uint64, fail.Error) {
	if tm == nil {
		return 0, fail.InvalidInstanceError()
	}
	if task == nil {
		return 0, fail.InvalidParameterCannotBeNilError("task")
	}

	tid, xerr := task.GetID()
	if xerr != nil {
		return 0, xerr
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if c, ok := tm.writeLocks[tid]; ok {
		return c, nil
	}
	return 0, nil
}

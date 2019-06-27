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
	tid := task.ID()
	// log.Debugf(">>> utils.concurrency.TaskedLock::RLock(%s)", tid)
	// defer log.Debugf("<<< utils.concurrency.TaskedLock::RLock(%s)", tid)

	tm.lock.Lock()

	if _, ok := tm.readLocks[tid]; ok {
		tm.readLocks[tid]++
		tm.lock.Unlock()
		return
	}
	tm.readLocks[tid] = 1
	if _, ok := tm.writeLocks[tid]; !ok {
		// log.Debugf("RLock(%s): really RLocking...", tid)
		tm.lock.Unlock()
		tm.rwmutex.RLock()
		return
	}
	tm.lock.Unlock()
	// log.Debugf("RLock(%s): using running write lock...", tid)
}

// RUnlock unregisters the lock for read for the context and unlock for read
// only if no lock for write is registered for the context
func (tm *taskedLock) RUnlock(task Task) {
	tid := task.ID()
	// log.Debugf(">>> utils.concurrency.lock.TaskedLock::RUnlock(%s)", tid)
	// defer log.Debugf("<<< utils.concurrency.lock.TaskedLock::RUnlock(%s)", tid)

	tm.lock.Lock()
	defer tm.lock.Unlock()

	if _, ok := tm.readLocks[tid]; !ok {
		panic(fmt.Sprintf("Can't RUnlock task %s: not RLocked", tid))
	}
	tm.readLocks[tid]--
	if tm.readLocks[tid] == 0 {
		delete(tm.readLocks, tid)
		// If not locked for write, actively unlock for read the RWMutex
		if _, ok := tm.writeLocks[tid]; !ok {
			// log.Debugf("RUnlock(%s): really RUnlocking...", tid)
			tm.rwmutex.RUnlock()
		}
		// log.Debugf("RUnlock(%s): in running write lock, doing nothing", tid)
	}
}

// Lock ...
func (tm *taskedLock) Lock(task Task) {
	tid := task.ID()
	// log.Debugf(">>> utils.concurrency.TaskedLock::Lock(%s)", tid)
	// defer log.Debugf("<<< utils.concurrency.TaskedLock::Lock(%s)", tid)

	tm.lock.Lock()

	// If already locked for write, increments counter for the task
	if _, ok := tm.writeLocks[tid]; ok {
		tm.writeLocks[tid]++
		tm.lock.Unlock()
		return
	}
	// If already lock for read, panic
	if _, ok := tm.readLocks[tid]; ok {
		panic(fmt.Sprintf("can't Lock task '%s': already RLocked", task.ID()))
	}
	// registers lock for read for the task and actively lock the RWMutex
	tm.writeLocks[tid] = 1
	tm.lock.Unlock()
	tm.rwmutex.Lock()
}

// Unlock ...
func (tm *taskedLock) Unlock(task Task) {
	tid := task.ID()
	// log.Debugf(">>> utils.concurrency.TaskedLock::Unlock(%s)", tid)
	// defer log.Debugf("<<< utils.concurrency.TaskedLock::Unlock(%s)", tid)

	tm.lock.Lock()
	defer tm.lock.Unlock()

	// a TaskedLock can be Locked then RLocked without problem,
	// but RUnlocks must have been done before Unlock.
	if _, ok := tm.readLocks[tid]; ok {
		panic(fmt.Sprintf("Can't Unlock task '%s': %d remaining RLock inside", tid, tm.readLocks[tid]))
	}
	if _, ok := tm.writeLocks[tid]; !ok {
		panic(fmt.Sprintf("Can't Unlock task '%s': not Locked", task.ID()))
	}
	tm.writeLocks[tid]--
	if tm.writeLocks[tid] == 0 {
		delete(tm.writeLocks, tid)
		tm.rwmutex.Unlock()
	}
}

// IsRLocked tells of the facet locks for read
func (tm *taskedLock) IsRLocked(task Task) bool {
	_, ok := tm.readLocks[task.ID()]
	return ok
}

// IsLocked tells if the facet locks for write
func (tm *taskedLock) IsLocked(task Task) bool {
	_, ok := tm.writeLocks[task.ID()]
	return ok
}

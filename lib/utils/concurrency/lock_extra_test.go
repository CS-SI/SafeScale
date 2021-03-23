// +build alltests,ignore

package concurrency

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWriteThenReadThenWrite(t *testing.T) {
	talo := NewTaskedLock()

	tawri, _ := NewUnbreakableTask()

	recall := func() string {
		err := talo.Lock(tawri)
		assert.Nil(t, err)
		defer func() {
			for {
				unlockErr := talo.Unlock(tawri)
				if unlockErr == nil {
					break
				} else {
					fmt.Println("recall() Unlock error:", unlockErr)
				}
				time.Sleep(time.Millisecond)
			}
		}()
		return "World"
	}

	reader := func() string {
		err := talo.RLock(tawri)
		assert.Nil(t, err)
		defer func() {
			err = talo.RUnlock(tawri)
			assert.Nil(t, err)
		}()

		fmt.Println(recall())
		return "Hello"
	}

	kall := func() {
		err := talo.Lock(tawri)
		assert.Nil(t, err)
		defer func() {
			for {
				unlockErr := talo.Unlock(tawri)
				if unlockErr == nil {
					break
				} else {
					fmt.Println("kall() Unlock error:", unlockErr)
				}
			}
		}()

		fmt.Println(reader())
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		kall()
	}()

	runOutOfTime := waitTimeout(&wg, time.Duration(50*time.Millisecond))
	if !runOutOfTime {
		t.Errorf("Failure: this should timeout !")
	}
}

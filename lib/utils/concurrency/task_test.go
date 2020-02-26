
package concurrency

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestDoesAbortReallyAbortOrIsJustFakeNews(t *testing.T) {
	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.StartWithTimeout(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		forever := true
		for forever {
			if t.Aborted() {
				forever = false
				break
			}
			time.Sleep(time.Duration(90) * time.Millisecond)
			fmt.Println("Forever young...")

		}
		return "I want to be forever young", nil
	}, nil, time.Duration(4000) * time.Millisecond)
	require.Nil(t, err)

	time.Sleep(time.Duration(2000) * time.Millisecond)
	// by now single should succeed
	err = single.Abort()

	fmt.Println("Aborted")

	// Nothing wrong should happen after this point...
	time.Sleep(time.Duration(2000) * time.Millisecond)

	require.Nil(t, err)
}


func TestAbortButThisTimeUsingTrueAbortChannel(t *testing.T) {
	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	trueAbort := make(chan struct{}) // TODO trueAbort dans TaskParameters ?
	single, err = single.StartWithTimeout(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		forever := true
		for forever {
			select {
			case <-trueAbort:
				fmt.Println("I'm Gotham's reckoning. Here to end the borrowed time you all have been living on.")
				forever = false
				break
			default:
				time.Sleep(time.Duration(90) * time.Millisecond)
				fmt.Println("Forever young...")
			}
		}
		return "I want to be forever young", nil
	}, nil, time.Duration(4000) * time.Millisecond)
	require.Nil(t, err)

	time.Sleep(time.Duration(2000) * time.Millisecond)

	err = single.Abort()
	trueAbort <- struct{}{}

	fmt.Println("Aborted")

	time.Sleep(time.Duration(2000) * time.Millisecond)

	require.Nil(t, err)
}
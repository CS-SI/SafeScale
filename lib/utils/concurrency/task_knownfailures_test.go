// +build alltests

package concurrency

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

func TestSingleTaskTryWaitUsingSubtasks(t *testing.T) {
	single, err := NewUnbreakableTask()
	require.NotNil(t, single)
	require.Nil(t, err)

	_, err = single.StartInSubtask(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	begin := time.Now()
	res, err := single.Wait()
	if err == nil {
		t.FailNow()
	}
	end := time.Since(begin)

	require.Nil(t, res)
	// require.NotNil(t, err)

	if end > time.Duration(2800)*time.Millisecond {
		t.FailNow()
	}
}

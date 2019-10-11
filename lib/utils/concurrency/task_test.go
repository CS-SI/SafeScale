package concurrency

import (
	"context"
	"fmt"
	"github.com/gophercloud/gophercloud/acceptance/tools"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

// FIXME The whole file task_test.go MUST pass UT flawlessly before using it confidently in foreman.go and controller.go

func TestNewTask(t *testing.T) {
	got, err := NewTask(nil)
	require.NotNil(t, got)
	require.Nil(t, err)

	theId, err := got.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theId)

	theTask, err := got.Start(nil, nil)
	require.Nil(t, err)
	require.NotNil(t, theTask)

	if theTask != nil {
		if stat, ok := theTask.GetStatus(); ok == nil {
			if stat != DONE {
				t.Errorf("Task should be DONE")
			}
		}
	}

	what, err := got.Start(nil, nil)
	require.NotNil(t, err)
	require.Nil(t, what)

	what, err = got.Reset()
	require.Nil(t, err)
	require.NotNil(t, what)
}

func TestWaitingGame(t *testing.T) {
	got, err := NewTask(nil)
	require.NotNil(t, got)
	require.Nil(t, err)

	theId, err := got.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theId)

	tarray := []Task{}

	for ind := 0; ind < 800; ind++ {
		got, err := NewTask(nil)
		require.Nil(t, err)
		require.NotNil(t, got)

		theTask, err := got.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			time.Sleep(time.Duration(tools.RandomInt(50, 250)) * time.Millisecond)
			return "waiting game", nil
		}, nil)
		if err == nil {
			tarray = append(tarray, theTask)
		} else {
			t.Errorf("Shouldn't happen")
		}
	}

	waited := 0
	for _, itta := range tarray {
		res, err := itta.Wait()
		require.Nil(t, err)
		require.NotNil(t, res)
		waited++
	}

	if waited != 800 {
		t.Errorf("Not enough waiting...: %d", waited)
	}
}

func TestChildrenWaitingGame(t *testing.T) {
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theId, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theId)

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			time.Sleep(time.Duration(tools.RandomInt(50, 250)) * time.Millisecond)
			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	res, err := overlord.Wait()

	require.Nil(t, err)
	require.NotEmpty(t, res)
}

func TestChildrenWaitingGameWithPanic(t *testing.T) {
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theId, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theId)

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			rint := tools.RandomInt(50, 250)
			time.Sleep(time.Duration(rint) * time.Millisecond)
			if rint > 100 {
				panic("Panic protection is needed")
			}

			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	res, err := overlord.Wait()
	require.NotNil(t, err)
	require.NotEmpty(t, res)

	ct := err.Error()
	if !strings.Contains(ct, "Panic protection") {
		t.Errorf("Expected to catch a Panic here...")
	}

	if !strings.Contains(ct, "panic happened") {
		t.Errorf("Expected to catch a Panic here...")
	}
}

func TestChildrenWaitingGameWithRandomError(t *testing.T) {
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theId, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theId)

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			rint := tools.RandomInt(50, 250)
			time.Sleep(time.Duration(rint) * time.Millisecond)
			if rint > 100 {
				return "", fmt.Errorf("suck it")
			}

			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	res, err := overlord.Wait()

	require.Nil(t, err)
	require.NotEmpty(t, res)
}

func TestChildrenTryWaitingGameWithRandomError(t *testing.T) {
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theId, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theId)

	for ind := 0; ind < 800; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			rint := tools.RandomInt(50, 250)
			time.Sleep(time.Duration(rint) * time.Millisecond)
			if rint > 100 {
				return "", fmt.Errorf("suck it")
			}

			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	begin := time.Now()
	waited, res, err := overlord.TryWait()
	end := time.Since(begin)

	if end >= (time.Millisecond * 200) {
		t.Errorf("It should have finished in 10s but it didn't !!")
	}

	require.False(t, waited)
	require.Nil(t, err)
	require.Nil(t, res)
}

func TestChildrenWaitingGameWithWait4EverTasks(t *testing.T) {
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theId, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theId)

	var tasks []Task

	for ind := 0; ind < 800; ind++ {
		rt, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			rint := tools.RandomInt(50, 250)
			time.Sleep(time.Duration(rint) * time.Millisecond)
			if rint > 150 {
				time.Sleep(time.Duration(14) * time.Second)
			}

			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
		tasks = append(tasks, rt)
	}

	var res TaskResult

	c := make(chan struct{})
	go func() {
		res, err = overlord.Wait()
		c <- struct{}{} // done
	}()

	select {
	case <-time.After(time.Duration(3) * time.Second):
		stats := overlord.Stats()

		if len(stats[RUNNING]) == 0 {
			t.Errorf("We should have dangling goroutines here...")
		} else {
			fmt.Printf("Ouch!: We have %d dead goroutines", len(stats[RUNNING]))
			require.True(t, len(stats[RUNNING]) > 0)
			return
		}

	case <-c:
		fmt.Printf("Good %s", res)
		return
	}

	t.Errorf("Unreachable")
}

func TestChildrenWaitingGameWithTimeouts(t *testing.T) {
	overlord, err := NewTaskGroup(nil)
	require.NotNil(t, overlord)
	require.Nil(t, err)

	theId, err := overlord.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theId)

	for ind := 0; ind < 10; ind++ {
		_, err := overlord.Start(func(t Task, parameters TaskParameters) (result TaskResult, e error) {
			rint := tools.RandomInt(3, 5)
			time.Sleep(time.Duration(rint) * time.Minute)

			return "waiting game", nil
		}, nil)
		if err != nil {
			t.Errorf("Unexpected: %s", err)
		}
	}

	begin := time.Now()
	waited, _, err := overlord.WaitFor(time.Duration(10) * time.Second)
	end := time.Since(begin)

	if end >= (time.Second * 11) {
		t.Errorf("It should have finished in 10s but it didn't !!")
	}

	if waited {
		t.Errorf("It shouldn't happen")
	}
}

func TestSingleTaskTryWait(t *testing.T) {
	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	begin := time.Now()
	waited, res, err := single.TryWait()
	end := time.Since(begin)

	require.False(t, waited)
	require.Nil(t, res)
	require.Nil(t, err)

	if end >= (time.Millisecond * 200) {
		t.Errorf("It should have finished fast but it didn't !!")
	}
}

func TestSingleTaskTryWaitCoreTask(t *testing.T) {
	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	_, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	begin := time.Now()
	waited, res, err := single.TryWait()
	end := time.Since(begin)

	require.False(t, waited)
	require.Nil(t, res)
	require.Nil(t, err)

	if end >= (time.Millisecond * 200) {
		t.Errorf("It should have finished fast but it didn't !!")
	}

	_, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.NotNil(t, err)

	time.Sleep(time.Duration(5) * time.Second)

	single, err = single.Reset()
	require.Nil(t, err)

	_, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	_, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.NotNil(t, err)
}

func TestSingleTaskTryWaitUsingSubtasks(t *testing.T) {
	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	_, err = single.StartInSubTask(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	begin := time.Now()
	res, err := single.Wait()
	end := time.Since(begin)

	_ = end

	require.Nil(t, res)
	require.NotNil(t, err)
}

func TestSingleTaskTryWaitOK(t *testing.T) {
	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	time.Sleep(time.Duration(5) * time.Second)
	// by now single should succeed

	begin := time.Now()
	waited, res, err := single.TryWait()
	end := time.Since(begin)

	require.True(t, waited)
	require.NotNil(t, res)
	require.Nil(t, err)

	if end >= (time.Millisecond * 200) {
		t.Errorf("It should have finished fast but it didn't !!")
	}
}

func TestSingleTaskWait(t *testing.T) {
	single, err := NewTask(nil)
	require.NotNil(t, single)
	require.Nil(t, err)

	single, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(3) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	begin := time.Now()
	res, err := single.Wait()
	end := time.Since(begin)

	require.NotNil(t, res)
	require.Nil(t, err)

	if end >= (time.Second*4) || end < (time.Second) {
		t.Errorf("It should have finished near 3s but it didn't !!")
	}
}

// FIXME This shows the problem with Tasks and contexts, run it a few times and it blocks
func TestChildrenWaitingGameWithContextTimeouts(t *testing.T) {
	ctx, cafu := context.WithTimeout(context.TODO(), 3*time.Second)
	single, err := NewTaskWithContext(ctx)
	require.NotNil(t, single)
	require.Nil(t, err)

	begin := time.Now()

	single, err = single.Start(func(t Task, parameters TaskParameters) (result TaskResult, err error) {
		time.Sleep(time.Duration(5) * time.Second)
		return "Ahhhh", nil
	}, nil)
	require.Nil(t, err)

	go func() {
		time.Sleep(time.Second)
		cafu()
	}()

	_, err = single.Wait()
	end := time.Since(begin)
	if err != nil {
		if !strings.Contains(err.Error(), "aborted") {
			t.Errorf("Why so serious ? it's just a failure cancelling a goroutine: %s", err.Error())
		}
	}

	if end > time.Second*5 {
		t.Errorf("We waited too much !")
	}
}

func TestChildrenWaitingGameWithContextDeadlines(t *testing.T) {
	t.Errorf("Why so serious ?")
}

func TestChildrenWaitingGameWithContextCancelfuncs(t *testing.T) {
	t.Errorf("Why so serious ?")
}

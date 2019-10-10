package concurrency

import (
	"fmt"
	"github.com/gophercloud/gophercloud/acceptance/tools"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

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
			fmt.Printf("WTF: %s", err)
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

	require.Nil(t, err)
	require.NotEmpty(t, res)
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
				return "", fmt.Errorf("Suck it")
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
				time.Sleep(time.Duration(rint) * time.Minute)
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
	case <-time.After(time.Duration(8) * time.Second):
		stats := overlord.Stats()
		t.Errorf("Ouch!: We have %d dead goroutines", len(stats[RUNNING]))

	case <-c:
		fmt.Printf("Good %s", res)
	}
}

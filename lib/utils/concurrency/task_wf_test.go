package concurrency

import (
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

func TestResultCheckWF(t *testing.T) {
	got, err := NewUnbreakableTask()
	require.NotNil(t, got)
	require.Nil(t, err)

	theID, err := got.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	_, err = got.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
		return "waiting game", nil
	}, nil, 10*time.Millisecond)
	if err != nil {
		t.Errorf("Shouldn't happen")
	}

	_, res, err := got.WaitFor(5 * time.Second) // look at next test, why different behavior ?
	require.NotNil(t, err)
	require.NotNil(t, res)

	tr, xerr := got.GetResult()
	require.Nil(t, xerr)
	require.NotNil(t, tr)
}

func TestResultCheckWithoutWF(t *testing.T) {
	got, err := NewUnbreakableTask()
	require.NotNil(t, got)
	require.Nil(t, err)

	theID, err := got.GetID()
	require.Nil(t, err)
	require.NotEmpty(t, theID)

	_, err = got.StartWithTimeout(func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
		time.Sleep(time.Duration(randomInt(50, 250)) * time.Millisecond)
		return "waiting game", nil
	}, nil, 10*time.Millisecond)
	if err != nil {
		t.Errorf("Shouldn't happen")
	}

	res, err := got.Wait()
	require.NotNil(t, err)
	require.NotNil(t, res)

	tr, xerr := got.GetResult()
	require.Nil(t, xerr)
	require.NotNil(t, tr)
}

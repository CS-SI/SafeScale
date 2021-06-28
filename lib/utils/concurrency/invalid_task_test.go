package concurrency

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func generator() Task {
	return &task{}
}

func tgGenerator() TaskGroup {
	return &taskGroup{}
}

func IsATask(i interface{}) bool {
	if _, ok := i.(Task); ok {
		return true
	}
	if _, ok := i.(*Task); ok {
		return true
	}
	return false
}

func IsATaskGroup(i interface{}) bool {
	if _, ok := i.(TaskGroup); ok {
		return true
	}
	if _, ok := i.(*TaskGroup); ok {
		return true
	}
	return false
}

func TestAGroupIsATask(t *testing.T) {
	require.False(t, IsATask(taskGroup{}))
}

func TestATaskIsAGroup(t *testing.T) {
	require.False(t, IsATaskGroup(task{}))
}

// that IS a problem (considering the 2 above tests and the one below), now we have to be extra careful in cluster and clustertasks (because of TaskActions)
// also, uncomment line 149 of this file to see another problem (variance of return types), the easy way out of this is remove taskgroup Wait keeping only WaitGroup
func TestAGroupIsATask2(t *testing.T) {
	require.False(t, IsATask(&taskGroup{}))
}

func TestATaskIsAGroup2(t *testing.T) {
	require.False(t, IsATaskGroup(&task{}))
}

func TestInvalidTask(t *testing.T) {
	got := generator()

	err := got.Abort()
	require.NotNil(t, err)

	_, err = got.Abortable()
	require.NotNil(t, err)

	got.Aborted()

	_ = got.DisarmAbortSignal()

	_, err = got.GetID()
	require.NotNil(t, err)

	_ = got.GetSignature()

	_, err = got.GetStatus()
	require.NotNil(t, err)

	_ = got.GetContext()
	require.NotNil(t, err)

	_, err = got.GetLastError()
	require.NotNil(t, err)

	_, err = got.GetResult()
	require.NotNil(t, err)

	err = got.SetID("")
	require.NotNil(t, err)

	_, err = got.Run(nil, nil)
	require.NotNil(t, err)

	_, err = got.Start(nil, nil)
	require.NotNil(t, err)

	_, err = got.StartWithTimeout(nil, nil, 0)
	require.NotNil(t, err)

	_, err = got.Start(nil, nil)
	require.NotNil(t, err)

	_, err = got.Wait()
	require.NotNil(t, err)

	_, _, err = got.TryWait()
	require.NotNil(t, err)
}

func TestInvalidTaskGroup(t *testing.T) {
	got := tgGenerator()

	err := got.Abort()
	require.NotNil(t, err)

	_, err = got.Abortable()
	require.NotNil(t, err)

	got.Aborted()

	_ = got.DisarmAbortSignal()

	_, err = got.GetID()
	require.NotNil(t, err)

	_ = got.GetSignature()

	_, err = got.GetStatus()
	require.NotNil(t, err)

	_ = got.GetContext()
	require.NotNil(t, err)

	_, err = got.GetLastError()
	require.NotNil(t, err)

	_, err = got.GetResult()
	require.NotNil(t, err)

	err = got.SetID("")
	require.NotNil(t, err)

	_, err = got.Run(nil, nil)
	require.NotNil(t, err)

	_, err = got.Start(nil, nil)
	require.NotNil(t, err)

	_, err = got.StartWithTimeout(nil, nil, 0)
	require.NotNil(t, err)

	// _, err = got.Wait()
	// require.NotNil(t, err)

	_, err = got.WaitGroup()
	require.NotNil(t, err)

	_, _, err = got.TryWaitGroup()
	require.NotNil(t, err)
}
